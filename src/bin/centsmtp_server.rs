//! centsmtp_server: receives mails over the encrypted tunnel, validates recipients,
//! relays them through AWS SES (SMTP interface) and archives every mail as an
//! individual .eml file (per client name / per day).
//! It also exposes an HTTP endpoint for AWS SNS (SES bounce/complaint/delivery events).

use anyhow::{anyhow, Context, Result};
use centsmtp::domain::{DomainChecker, Verdict};
use centsmtp::lists::Lists;
use centsmtp::proto::{
    generate_key, MailRequest, MailResponse, RcptResult, SecureChannel, Status, MAX_MESSAGE_SIZE,
};
use centsmtp::sns::{self, SnsState};
use clap::Parser;
use lettre::{
    address::Envelope,
    transport::smtp::authentication::Credentials,
    Address, SmtpTransport, Transport,
};
use rand::RngCore;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use time::macros::format_description;
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "centsmtp_server", version, about = "SMTP bridge server: encrypted tunnel -> AWS SES, with archiving")]
struct Args {
    /// Address to listen on for centsmtp_client connections.
    #[arg(long, env = "CENTSMTP_LISTEN", default_value = "0.0.0.0:7025")]
    listen: String,

    /// Pre-shared key shared with the clients (see --gen-key).
    #[arg(long, env = "CENTSMTP_KEY", hide_env_values = true, required_unless_present = "gen_key")]
    key: Option<String>,

    /// SES SMTP endpoint.
    #[arg(long, env = "CENTSMTP_SMTP_HOST", default_value = "email-smtp.us-east-1.amazonaws.com")]
    smtp_host: String,

    /// SES SMTP port (587 = STARTTLS, 465 = implicit TLS).
    #[arg(long, env = "CENTSMTP_SMTP_PORT", default_value_t = 587)]
    smtp_port: u16,

    /// SES SMTP username.
    #[arg(long, env = "CENTSMTP_SMTP_USER", required_unless_present = "gen_key")]
    smtp_user: Option<String>,

    /// SES SMTP password.
    #[arg(long, env = "CENTSMTP_SMTP_PASS", hide_env_values = true, required_unless_present = "gen_key")]
    smtp_pass: Option<String>,

    /// Directory where mails are archived: <dir>/<client name>/<date>/*.eml
    #[arg(long, env = "CENTSMTP_ARCHIVE_DIR", default_value = "archive")]
    archive_dir: PathBuf,

    /// Directory holding whitelist.json, blacklist.json and events.jsonl.
    #[arg(long, env = "CENTSMTP_DATA_DIR", default_value = "data")]
    data_dir: PathBuf,

    /// HTTP listen address for the AWS SNS endpoint (POST /sns/<token>).
    #[arg(long, env = "CENTSMTP_SNS_LISTEN", default_value = "127.0.0.1:7026")]
    sns_listen: String,

    /// Secret path token of the SNS endpoint. The endpoint is disabled when not set.
    #[arg(long, env = "CENTSMTP_SNS_TOKEN", hide_env_values = true)]
    sns_token: Option<String>,

    /// Only accept SNS messages from this topic ARN (optional).
    #[arg(long, env = "CENTSMTP_SNS_TOPIC_ARN")]
    sns_topic_arn: Option<String>,

    /// SQS queue URL receiving SES events via SNS. The server polls it (outbound only).
    #[arg(long, env = "CENTSMTP_SQS_URL")]
    sqs_url: Option<String>,

    /// URL of an open-source disposable-email domain blocklist (one domain per line),
    /// downloaded periodically. Recipients on it are rejected. Use "off" to disable.
    #[arg(long, env = "CENTSMTP_BLOCKLIST_URL", default_value = centsmtp::blocklist::DEFAULT_URL)]
    blocklist_url: String,

    /// Hours between blocklist updates.
    #[arg(long, env = "CENTSMTP_BLOCKLIST_INTERVAL_HOURS", default_value_t = 24)]
    blocklist_interval_hours: u64,

    /// AWS access key id for SQS (needs sqs:ReceiveMessage and sqs:DeleteMessage).
    #[arg(long, env = "AWS_ACCESS_KEY_ID")]
    aws_access_key_id: Option<String>,

    /// AWS secret access key for SQS.
    #[arg(long, env = "AWS_SECRET_ACCESS_KEY", hide_env_values = true)]
    aws_secret_access_key: Option<String>,

    /// AWS session token (only for temporary credentials).
    #[arg(long, env = "AWS_SESSION_TOKEN", hide_env_values = true)]
    aws_session_token: Option<String>,

    /// Maximum number of concurrent client connections.
    #[arg(long, default_value_t = 64)]
    max_connections: usize,

    /// Print a freshly generated random key and exit.
    #[arg(long)]
    gen_key: bool,
}

struct State {
    key: String,
    transport: SmtpTransport,
    archive_dir: PathBuf,
    lists: Arc<Lists>,
    checker: DomainChecker,
}

/// Loads `centsmtp.conf` (or the file named by CENTSMTP_CONFIG) into the environment
/// before the runtime and the argument parser start.
fn main() -> Result<()> {
    let path = std::env::var("CENTSMTP_CONFIG").unwrap_or_else(|_| "centsmtp.conf".into());
    centsmtp::config::load_env_file(Path::new(&path))?;
    run()
}

#[tokio::main]
async fn run() -> Result<()> {
    let args = Args::parse();
    if args.gen_key {
        println!("{}", generate_key());
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let creds = Credentials::new(args.smtp_user.unwrap(), args.smtp_pass.unwrap());
    let builder = if args.smtp_port == 465 {
        SmtpTransport::relay(&args.smtp_host)
    } else {
        SmtpTransport::starttls_relay(&args.smtp_host)
    }
    .context("invalid SMTP host")?;
    let transport = builder
        .port(args.smtp_port)
        .credentials(creds)
        .timeout(Some(Duration::from_secs(60)))
        .build();

    tokio::fs::create_dir_all(&args.archive_dir)
        .await
        .context("cannot create archive directory")?;
    let lists = Arc::new(Lists::load(&args.data_dir)?);

    // Pick up manual edits of whitelist.json.
    {
        let lists = lists.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                match lists.reload_whitelist_if_changed() {
                    Ok(true) => info!("whitelist.json reloaded"),
                    Ok(false) => {}
                    Err(e) => warn!("cannot reload whitelist.json: {e:#}"),
                }
            }
        });
    }

    // Open-source disposable-email blocklist: cached copy first, then periodic updates.
    if args.blocklist_url.eq_ignore_ascii_case("off") {
        info!("disposable-email blocklist disabled");
    } else {
        let path = args.data_dir.join("disposable_domains.txt");
        centsmtp::blocklist::load_cache(&lists, &path);
        let interval = Duration::from_secs(args.blocklist_interval_hours.max(1) * 3600);
        tokio::spawn(centsmtp::blocklist::run(lists.clone(), args.blocklist_url.clone(), path, interval));
    }

    // AWS SNS endpoint.
    if let Some(queue_url) = args.sqs_url {
        let (Some(access_key), Some(secret_key)) = (args.aws_access_key_id, args.aws_secret_access_key) else {
            return Err(anyhow!("--sqs-url needs --aws-access-key-id and --aws-secret-access-key"));
        };
        let cfg = centsmtp::sqs::SqsConfig {
            queue_url,
            access_key,
            secret_key,
            session_token: args.aws_session_token,
            topic_arn: args.sns_topic_arn.clone(),
            events_path: args.data_dir.join("events.jsonl"),
        };
        let lists = lists.clone();
        tokio::spawn(async move {
            if let Err(e) = centsmtp::sqs::run(cfg, lists).await {
                error!("SQS poller stopped: {e:#}");
            }
        });
    }
    match args.sns_token {
        Some(token) => {
            let listener = TcpListener::bind(&args.sns_listen)
                .await
                .with_context(|| format!("cannot listen on {}", args.sns_listen))?;
            info!("SNS endpoint listening on http://{}/sns/<token>", args.sns_listen);
            let st = Arc::new(SnsState {
                lists: lists.clone(),
                token,
                topic_arn: args.sns_topic_arn,
                events_path: args.data_dir.join("events.jsonl"),
                http: reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?,
            });
            tokio::spawn(async move {
                if let Err(e) = sns::serve(listener, st).await {
                    error!("SNS endpoint stopped: {e:#}");
                }
            });
        }
        None => info!("HTTP SNS endpoint disabled (set --sns-token to enable it)"),
    }

    let state = Arc::new(State {
        key: args.key.unwrap(),
        transport,
        archive_dir: args.archive_dir,
        lists,
        checker: DomainChecker::new().context("cannot initialise DNS resolver")?,
    });

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("cannot listen on {}", args.listen))?;
    info!("centsmtp_server listening on {} -> {}:{}", args.listen, args.smtp_host, args.smtp_port);

    let permits = Arc::new(Semaphore::new(args.max_connections));
    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, peer) = match res {
                    Ok(v) => v,
                    Err(e) => { warn!("accept failed: {e}"); continue; }
                };
                let Ok(permit) = permits.clone().acquire_owned().await else { break };
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, state).await {
                        warn!("[{peer}] connection error: {e:#}");
                    }
                    drop(permit);
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_conn(stream: TcpStream, peer: SocketAddr, state: Arc<State>) -> Result<()> {
    stream.set_nodelay(true).ok();
    let mut ch = SecureChannel::accept(stream, state.key.as_bytes()).await?;
    let frame = timeout(Duration::from_secs(60), ch.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for request"))??;
    let req: MailRequest = bincode::deserialize(&frame).context("malformed request")?;
    drop(frame);

    let resp = process(&state, req, peer).await;
    ch.send(&bincode::serialize(&resp)?).await?;
    Ok(())
}

fn new_id() -> String {
    let mut b = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Client names become directory names: keep it to a safe character set.
fn sanitize_name(name: &str) -> String {
    let s: String = name
        .chars()
        .take(64)
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() { "unknown".into() } else { s }
}

fn fail_all(req: &MailRequest, status: Status, message: &str) -> Vec<RcptResult> {
    req.rcpt_to
        .iter()
        .map(|a| RcptResult { addr: a.clone(), status, message: message.to_string() })
        .collect()
}

fn finish(id: String, rcpts: Vec<RcptResult>) -> MailResponse {
    let sent = rcpts.iter().filter(|r| r.status == Status::Sent).count();
    let status = if sent > 0 {
        Status::Sent
    } else {
        rcpts.first().map(|r| r.status).unwrap_or(Status::Internal)
    };
    let failures: Vec<String> = rcpts
        .iter()
        .filter(|r| r.status != Status::Sent)
        .map(|r| format!("{}: {} ({})", r.addr, r.status.as_str(), r.message))
        .collect();
    let message = match (sent, failures.is_empty()) {
        (_, true) => format!("queued as {id}"),
        (0, false) => failures.join("; "),
        (_, false) => format!("queued as {id}; not sent: {}", failures.join("; ")),
    };
    MailResponse { id, status, message, rcpts }
}

async fn process(state: &Arc<State>, req: MailRequest, peer: SocketAddr) -> MailResponse {
    let id = new_id();
    let client = sanitize_name(&req.client_name);
    let req = Arc::new(req);
    info!(
        "[{peer}] mail {id} client={client}: from <{}> to {:?} ({} bytes)",
        req.mail_from, req.rcpt_to, req.data.len()
    );

    let mut attempted = false;
    let rcpts = process_inner(state, &req, &id, &mut attempted).await;
    let resp = finish(id.clone(), rcpts);

    let sent_any = resp.status == Status::Sent;
    let label = if sent_any { "sent" } else if attempted { "failed" } else { "rejected" };
    if !sent_any {
        warn!("mail {id}: {}", resp.message);
    }
    archive(&state.archive_dir, &client, &id, label, &req, &resp.message).await;
    resp
}

async fn process_inner(state: &Arc<State>, req: &Arc<MailRequest>, id: &str, attempted: &mut bool) -> Vec<RcptResult> {
    if req.rcpt_to.is_empty() {
        return vec![RcptResult { addr: String::new(), status: Status::InvalidAddress, message: "no recipients".into() }];
    }
    if req.data.len() > MAX_MESSAGE_SIZE {
        return fail_all(req, Status::TooLarge, "message too large");
    }
    let from = if req.mail_from.is_empty() {
        None
    } else {
        match req.mail_from.parse::<Address>() {
            Ok(a) => Some(a),
            Err(_) => return fail_all(req, Status::InvalidAddress, "invalid sender address"),
        }
    };

    let mut results: Vec<RcptResult> = Vec::new();
    let mut valid: Vec<Address> = Vec::new();
    let mut seen = HashSet::new();
    for raw in &req.rcpt_to {
        if !seen.insert(raw.to_ascii_lowercase()) {
            continue;
        }
        let mut fail = |status: Status, message: String| {
            results.push(RcptResult { addr: raw.clone(), status, message });
        };
        let Ok(addr) = raw.parse::<Address>() else {
            fail(Status::InvalidAddress, "invalid address".into());
            continue;
        };
        if let Some(reason) = state.lists.blacklist_reason(raw) {
            fail(Status::Blacklisted, format!("address is blacklisted: {reason}"));
            continue;
        }
        if !state.lists.is_whitelisted(addr.domain()) {
            if let Some(entry) = state.lists.disposable_match(addr.domain()) {
                fail(Status::Blacklisted, format!("domain {entry} is on the disposable-email blocklist"));
                continue;
            }
            if let Some(real) = state.lists.typo_suggestion(addr.domain()) {
                fail(Status::InvalidDomain, format!("possible typo in domain, did you mean {real}?"));
                continue;
            }
            match state.checker.check(addr.domain()).await {
                Verdict::Valid => {}
                Verdict::Invalid(why) => {
                    fail(Status::InvalidDomain, why);
                    continue;
                }
                Verdict::Unknown(why) => {
                    fail(Status::DomainCheckFailed, why);
                    continue;
                }
            }
        }
        valid.push(addr);
    }

    if valid.is_empty() {
        return results;
    }

    let envelope = match Envelope::new(from, valid.clone()) {
        Ok(e) => e,
        Err(e) => {
            results.extend(valid.iter().map(|a| RcptResult {
                addr: a.to_string(),
                status: Status::InvalidAddress,
                message: e.to_string(),
            }));
            return results;
        }
    };

    *attempted = true;
    let transport = state.transport.clone();
    let job_req = req.clone();
    let sent = tokio::task::spawn_blocking(move || transport.send_raw(&envelope, &job_req.data)).await;

    let (status, message) = match sent {
        Ok(Ok(r)) => {
            let ses = r.message().collect::<Vec<_>>().join(" ");
            info!("mail {id}: handed to SES ({ses})");
            (Status::Sent, format!("accepted by SES ({ses})"))
        }
        Ok(Err(e)) => {
            error!("mail {id}: SES send failed: {e}");
            let status = if e.is_permanent() { Status::RelayRejected } else { Status::RelayTemporary };
            (status, format!("SES: {e}"))
        }
        Err(e) => {
            error!("mail {id}: internal error: {e}");
            (Status::Internal, format!("internal error: {e}"))
        }
    };
    results.extend(valid.iter().map(|a| RcptResult { addr: a.to_string(), status, message: message.clone() }));
    results
}

fn one_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

/// Stores the mail as `<dir>/<client>/<date>/<timestamp>_<id>_<status>.eml`.
/// A few `X-Centsmtp-*` trace headers are prepended to carry the envelope and the result.
async fn archive(dir: &Path, client: &str, id: &str, status: &str, req: &MailRequest, detail: &str) {
    let now = OffsetDateTime::now_utc();
    let (Ok(day), Ok(ts)) = (
        now.format(format_description!("[year]-[month]-[day]")),
        now.format(format_description!("[year][month][day]T[hour][minute][second]Z")),
    ) else {
        error!("mail {id}: cannot format timestamp");
        return;
    };

    let day_dir = dir.join(client).join(day);
    if let Err(e) = tokio::fs::create_dir_all(&day_dir).await {
        error!("mail {id}: cannot create {}: {e}", day_dir.display());
        return;
    }
    let path = day_dir.join(format!("{ts}_{id}_{status}.eml"));

    let mut buf = Vec::with_capacity(req.data.len() + 512);
    let header = format!(
        "X-Centsmtp-Id: {id}\r\nX-Centsmtp-Client: {client}\r\nX-Centsmtp-Status: {status}\r\nX-Centsmtp-Detail: {}\r\nX-Centsmtp-Envelope-From: {}\r\nX-Centsmtp-Envelope-To: {}\r\n",
        one_line(detail),
        one_line(&req.mail_from),
        one_line(&req.rcpt_to.join(", ")),
    );
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(&req.data);

    match tokio::fs::write(&path, &buf).await {
        Ok(()) => info!("mail {id}: archived to {}", path.display()),
        Err(e) => error!("mail {id}: cannot write {}: {e}", path.display()),
    }
}
