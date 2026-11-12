//! HTTP endpoint receiving AWS SNS notifications about SES delivery results.
//!
//! `POST /sns/<token>` - the token is a shared secret that must be part of the URL
//! configured in the SNS subscription. Handled message types:
//! * SubscriptionConfirmation: confirmed automatically (https + *.amazonaws.com only)
//! * Notification (SES Bounce / Complaint / Delivery / Reject events):
//!   permanent bounces and complaints put the recipient on the blacklist.

use crate::lists::Lists;
use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{info, warn};

pub struct SnsState {
    pub lists: Arc<Lists>,
    pub token: String,
    pub topic_arn: Option<String>,
    /// Every processed SES event is appended here as one JSON line.
    pub events_path: PathBuf,
    pub http: reqwest::Client,
}

#[derive(Deserialize)]
struct SnsEnvelope {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Message")]
    message: Option<String>,
    #[serde(rename = "SubscribeURL")]
    subscribe_url: Option<String>,
    #[serde(rename = "TopicArn")]
    topic_arn: Option<String>,
}

pub async fn serve(listener: TcpListener, state: Arc<SnsState>) -> Result<()> {
    let app = Router::new().route("/sns/{token}", post(handle)).with_state(state);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle(State(st): State<Arc<SnsState>>, Path(token): Path<String>, body: String) -> StatusCode {
    if !bool::from(token.as_bytes().ct_eq(st.token.as_bytes())) {
        return StatusCode::NOT_FOUND;
    }
    let Ok(env) = serde_json::from_str::<SnsEnvelope>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    if let (Some(expected), Some(actual)) = (&st.topic_arn, &env.topic_arn) {
        if expected != actual {
            warn!("SNS message from unexpected topic {actual}");
            return StatusCode::FORBIDDEN;
        }
    }

    match env.kind.as_str() {
        "SubscriptionConfirmation" => {
            let Some(url) = env.subscribe_url else { return StatusCode::BAD_REQUEST };
            let ok = url::is_aws_https(&url);
            if !ok {
                warn!("refusing SubscribeURL outside amazonaws.com: {url}");
                return StatusCode::BAD_REQUEST;
            }
            match st.http.get(&url).send().await.and_then(|r| r.error_for_status()) {
                Ok(_) => info!("SNS subscription confirmed"),
                Err(e) => {
                    warn!("SNS subscription confirmation failed: {e}");
                    return StatusCode::BAD_GATEWAY;
                }
            }
        }
        "Notification" => {
            let Some(msg) = env.message else { return StatusCode::BAD_REQUEST };
            if let Err(e) = process_ses_event(&st.lists, &st.events_path, &msg).await {
                warn!("cannot process SES event: {e:#}");
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
        _ => {}
    }
    StatusCode::OK
}

mod url {
    /// Only https URLs on amazonaws.com hosts are fetched.
    pub fn is_aws_https(u: &str) -> bool {
        let Some(rest) = u.strip_prefix("https://") else { return false };
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        !host.contains('@') && !host.contains(':') && host.ends_with(".amazonaws.com")
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Handles one SES event JSON document (the `Message` of an SNS notification).
pub async fn process_ses_event(lists: &Lists, events_path: &FsPath, message: &str) -> Result<()> {
    let v: Value = serde_json::from_str(message)?;
    let kind = v
        .get("notificationType")
        .or_else(|| v.get("eventType"))
        .and_then(Value::as_str)
        .unwrap_or("Unknown");
    let message_id = v.get("mail").map(|m| str_of(m, "messageId")).unwrap_or("").to_string();

    let mut recipients: Vec<String> = Vec::new();
    let mut detail = String::new();

    match kind {
        "Bounce" => {
            let b = &v["bounce"];
            let (btype, bsub) = (str_of(b, "bounceType"), str_of(b, "bounceSubType"));
            detail = format!("{btype}/{bsub}");
            for r in b["bouncedRecipients"].as_array().into_iter().flatten() {
                let addr = str_of(r, "emailAddress");
                if addr.is_empty() {
                    continue;
                }
                recipients.push(addr.to_string());
                if btype == "Permanent" {
                    let reason = format!("bounce {btype}/{bsub}: {}", str_of(r, "diagnosticCode"));
                    if lists.blacklist_add(addr, &reason)? {
                        info!("blacklisted {addr} ({reason})");
                    }
                }
            }
        }
        "Complaint" => {
            let c = &v["complaint"];
            detail = format!("complaint {}", str_of(c, "complaintFeedbackType"));
            for r in c["complainedRecipients"].as_array().into_iter().flatten() {
                let addr = str_of(r, "emailAddress");
                if addr.is_empty() {
                    continue;
                }
                recipients.push(addr.to_string());
                if lists.blacklist_add(addr, &detail)? {
                    info!("blacklisted {addr} ({detail})");
                }
            }
        }
        "Delivery" => {
            recipients = v["delivery"]["recipients"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| r.as_str().map(String::from))
                .collect();
        }
        "Reject" => {
            detail = str_of(&v["reject"], "reason").to_string();
            recipients = v["mail"]["destination"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| r.as_str().map(String::from))
                .collect();
        }
        _ => {}
    }

    info!("SES event {kind} message={message_id} recipients={recipients:?} {detail}");
    let line = json!({
        "time": OffsetDateTime::now_utc().format(&Rfc3339)?,
        "type": kind,
        "messageId": message_id,
        "recipients": recipients,
        "detail": detail,
    });
    let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(events_path).await?;
    f.write_all(format!("{line}\n").as_bytes()).await?;
    Ok(())
}
