//! centsmtp_client: exposes a plain local SMTP server and forwards each accepted mail
//! over the encrypted tunnel to centsmtp_server.

use anyhow::{anyhow, Context, Result};
use centsmtp::proto::{generate_key, MailRequest, MailResponse, SecureChannel, Status, MAX_MESSAGE_SIZE};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_RCPTS: usize = 100;
const MAX_DATA_LINE: u64 = 1 << 20;

#[derive(Parser)]
#[command(name = "centsmtp_client", version, about = "SMTP bridge client: local SMTP server -> encrypted tunnel -> centsmtp_server")]
struct Args {
    /// Name of this client instance (letters, digits, '.', '_' and '-'). Used for the log file
    /// and for the server-side archive directory. Run several instances with different names
    /// and different --listen ports.
    #[arg(long, env = "CENTSMTP_NAME", value_parser = parse_name, required_unless_present = "gen_key")]
    name: Option<String>,

    /// Local SMTP listen address.
    #[arg(long, env = "CENTSMTP_LISTEN", default_value = "127.0.0.1:25")]
    listen: String,

    /// Directory for the per-instance result log (<dir>/<name>.log).
    #[arg(long, env = "CENTSMTP_LOG_DIR", default_value = "logs")]
    log_dir: PathBuf,

    /// centsmtp_server address (host:port).
    #[arg(long, env = "CENTSMTP_SERVER", required_unless_present = "gen_key")]
    server: Option<String>,

    /// Pre-shared key shared with the server.
    #[arg(long, env = "CENTSMTP_KEY", hide_env_values = true, required_unless_present = "gen_key")]
    key: Option<String>,

    /// Print a freshly generated random key and exit.
    #[arg(long)]
    gen_key: bool,
}

fn parse_name(s: &str) -> Result<String, String> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(s.to_string())
    } else {
        Err("must be 1-64 chars of [A-Za-z0-9._-] and not start with '.'".into())
    }
}

struct Config {
    name: String,
    server: String,
    key: String,
    log: ResultLog,
}

/// Append-only log of request results: only the target address and the server's answer,
/// never the mail content.
struct ResultLog {
    file: Mutex<File>,
}

impl ResultLog {
    async fn open(dir: &Path, name: &str) -> Result<Self> {
        tokio::fs::create_dir_all(dir).await.context("cannot create log directory")?;
        let path = dir.join(format!("{name}.log"));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("cannot open {}", path.display()))?;
        Ok(Self { file: Mutex::new(file) })
    }

    async fn record(&self, rcpt: &str, status: &str, message: &str) {
        let ts = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default();
        let line = format!("{ts} {} {status} {}\n", one_line(rcpt), one_line(message));
        info!("result {} {status} {}", one_line(rcpt), one_line(message));
        if let Err(e) = self.file.lock().await.write_all(line.as_bytes()).await {
            warn!("cannot write result log: {e}");
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.gen_key {
        println!("{}", generate_key());
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let name = args.name.unwrap();
    let log = ResultLog::open(&args.log_dir, &name).await?;
    let cfg = Arc::new(Config { name, server: args.server.unwrap(), key: args.key.unwrap(), log });
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("cannot listen on {}", args.listen))?;
    info!("centsmtp_client[{}] SMTP listening on {} -> {}", cfg.name, args.listen, cfg.server);

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, peer) = match res {
                    Ok(v) => v,
                    Err(e) => { warn!("accept failed: {e}"); continue; }
                };
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = session(stream, cfg).await {
                        warn!("[{peer}] session error: {e:#}");
                    }
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

async fn forward(cfg: &Config, req: &MailRequest) -> Result<MailResponse> {
    let stream = timeout(Duration::from_secs(10), TcpStream::connect(&cfg.server))
        .await
        .map_err(|_| anyhow!("connect timed out"))??;
    stream.set_nodelay(true).ok();
    let mut ch = SecureChannel::connect(stream, cfg.key.as_bytes()).await?;
    ch.send(&bincode::serialize(req)?).await?;
    let frame = timeout(Duration::from_secs(120), ch.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for server response"))??;
    Ok(bincode::deserialize(&frame)?)
}

async fn reply(wr: &mut OwnedWriteHalf, line: &str) -> Result<()> {
    wr.write_all(line.as_bytes()).await?;
    wr.write_all(b"\r\n").await?;
    Ok(())
}

async fn read_line<R: AsyncBufRead + Unpin>(rd: &mut R, buf: &mut Vec<u8>, limit: u64) -> Result<usize> {
    buf.clear();
    let n = timeout(IDLE_TIMEOUT, (&mut *rd).take(limit).read_until(b'\n', buf))
        .await
        .map_err(|_| anyhow!("idle timeout"))??;
    Ok(n)
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

/// Parses `<addr> params...` (also tolerates a missing `<>`), returns (addr, params).
fn parse_path(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    let (addr, params) = if let Some(rest) = s.strip_prefix('<') {
        let end = rest.find('>')?;
        (&rest[..end], &rest[end + 1..])
    } else {
        match s.split_once(' ') {
            Some((a, p)) => (a, p),
            None => (s, ""),
        }
    };
    // Drop an obsolete source route: "@a,@b:user@host".
    let addr = if addr.starts_with('@') { addr.split_once(':').map(|x| x.1).unwrap_or(addr) } else { addr };
    Some((addr.trim().to_string(), params))
}

async fn session(stream: TcpStream, cfg: Arc<Config>) -> Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    reply(&mut wr, "220 centsmtp ESMTP ready").await?;

    let mut from: Option<String> = None;
    let mut rcpts: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    loop {
        let n = read_line(&mut rd, &mut buf, 4096).await?;
        if n == 0 {
            break;
        }
        if !buf.ends_with(b"\n") {
            reply(&mut wr, "500 line too long").await?;
            break;
        }
        let line = String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string();
        let (cmd, rest) = match line.split_once(' ') {
            Some((c, r)) => (c.to_ascii_uppercase(), r.trim()),
            None => (line.to_ascii_uppercase(), ""),
        };

        match cmd.as_str() {
            "EHLO" | "HELO" => {
                if cmd == "EHLO" {
                    let text = format!(
                        "250-centsmtp\r\n250-SIZE {MAX_MESSAGE_SIZE}\r\n250-8BITMIME\r\n250-PIPELINING\r\n250 AUTH PLAIN LOGIN"
                    );
                    reply(&mut wr, &text).await?;
                } else {
                    reply(&mut wr, "250 centsmtp").await?;
                }
                from = None;
                rcpts.clear();
            }
            "AUTH" => {
                // The listener is local only; any credentials are accepted so that
                // mail clients that insist on authentication keep working.
                let mut parts = rest.split_whitespace();
                match parts.next().map(|m| m.to_ascii_uppercase()).as_deref() {
                    Some("PLAIN") => {
                        if parts.next().is_none() {
                            reply(&mut wr, "334 ").await?;
                            read_line(&mut rd, &mut buf, 4096).await?;
                        }
                        reply(&mut wr, "235 2.7.0 Authentication successful").await?;
                    }
                    Some("LOGIN") => {
                        if parts.next().is_none() {
                            reply(&mut wr, "334 VXNlcm5hbWU6").await?;
                            read_line(&mut rd, &mut buf, 4096).await?;
                        }
                        reply(&mut wr, "334 UGFzc3dvcmQ6").await?;
                        read_line(&mut rd, &mut buf, 4096).await?;
                        reply(&mut wr, "235 2.7.0 Authentication successful").await?;
                    }
                    _ => reply(&mut wr, "504 Unrecognized authentication type").await?,
                }
            }
            "MAIL" => {
                let Some((addr, params)) = strip_prefix_ci(rest, "FROM:").and_then(parse_path) else {
                    reply(&mut wr, "501 Syntax: MAIL FROM:<address>").await?;
                    continue;
                };
                let too_big = params.split_whitespace().any(|p| {
                    p.to_ascii_uppercase()
                        .strip_prefix("SIZE=")
                        .and_then(|v| v.parse::<usize>().ok())
                        .is_some_and(|v| v > MAX_MESSAGE_SIZE)
                });
                if too_big {
                    reply(&mut wr, "552 Message size exceeds limit").await?;
                    continue;
                }
                from = Some(addr);
                rcpts.clear();
                reply(&mut wr, "250 OK").await?;
            }
            "RCPT" => {
                if from.is_none() {
                    reply(&mut wr, "503 Need MAIL command first").await?;
                    continue;
                }
                let Some((addr, _)) = strip_prefix_ci(rest, "TO:").and_then(parse_path) else {
                    reply(&mut wr, "501 Syntax: RCPT TO:<address>").await?;
                    continue;
                };
                if addr.is_empty() {
                    reply(&mut wr, "501 Empty recipient").await?;
                } else if rcpts.len() >= MAX_RCPTS {
                    reply(&mut wr, "452 Too many recipients").await?;
                } else {
                    rcpts.push(addr);
                    reply(&mut wr, "250 OK").await?;
                }
            }
            "DATA" => {
                if from.is_none() || rcpts.is_empty() {
                    reply(&mut wr, "503 Need MAIL and RCPT first").await?;
                    continue;
                }
                reply(&mut wr, "354 End data with <CR><LF>.<CR><LF>").await?;

                let mut data: Vec<u8> = Vec::new();
                let mut too_big = false;
                loop {
                    let n = read_line(&mut rd, &mut buf, MAX_DATA_LINE).await?;
                    if n == 0 {
                        return Ok(()); // client vanished mid-message
                    }
                    let ended = buf.ends_with(b"\n");
                    if !ended && n as u64 >= MAX_DATA_LINE {
                        reply(&mut wr, "500 line too long").await?;
                        return Ok(());
                    }
                    let l = buf.strip_suffix(b"\n").unwrap_or(&buf);
                    let l = l.strip_suffix(b"\r").unwrap_or(l);
                    if l == b"." {
                        break;
                    }
                    if too_big {
                        continue;
                    }
                    let l = if l.starts_with(b"..") { &l[1..] } else { l };
                    data.extend_from_slice(l);
                    data.extend_from_slice(b"\r\n");
                    if data.len() > MAX_MESSAGE_SIZE {
                        too_big = true;
                        data = Vec::new();
                    }
                }

                if too_big {
                    reply(&mut wr, "552 Message size exceeds limit").await?;
                } else {
                    let req = MailRequest {
                        client_name: cfg.name.clone(),
                        mail_from: from.take().unwrap_or_default(),
                        rcpt_to: std::mem::take(&mut rcpts),
                        data,
                    };
                    match forward(&cfg, &req).await {
                        Ok(r) => {
                            for rc in &r.rcpts {
                                cfg.log.record(&rc.addr, rc.status.as_str(), &rc.message).await;
                            }
                            let msg = one_line(&r.message);
                            let line = match r.status {
                                Status::Sent => format!("250 OK {msg}"),
                                Status::TooLarge => format!("552 {msg}"),
                                s if s.is_temporary() => format!("451 {msg}"),
                                _ => format!("550 {msg}"),
                            };
                            reply(&mut wr, &line).await?;
                        }
                        Err(e) => {
                            let why = format!("{e:#}");
                            warn!("forward failed: {why}");
                            for rcpt in &req.rcpt_to {
                                cfg.log.record(rcpt, "RELAY_UNAVAILABLE", &why).await;
                            }
                            reply(&mut wr, &format!("451 Relay unavailable: {}", one_line(&why))).await?;
                        }
                    }
                }
                from = None;
                rcpts.clear();
            }
            "RSET" => {
                from = None;
                rcpts.clear();
                reply(&mut wr, "250 OK").await?;
            }
            "NOOP" => reply(&mut wr, "250 OK").await?,
            "VRFY" => reply(&mut wr, "252 Cannot VRFY user").await?,
            "QUIT" => {
                reply(&mut wr, "221 Bye").await?;
                break;
            }
            "" => reply(&mut wr, "500 Empty command").await?,
            _ => reply(&mut wr, "502 Command not implemented").await?,
        }
    }
    Ok(())
}

fn one_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}
