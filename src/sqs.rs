//! Pulls SES events (delivered through SNS -> SQS) from an SQS queue with long polling.
//! Only outbound HTTPS connections are needed; no inbound port has to be opened.
//!
//! Requests use the SQS JSON protocol and are signed with AWS Signature V4.

use crate::lists::Lists;
use crate::sns::process_ses_event;
use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::macros::format_description;
use time::OffsetDateTime;
use tracing::{info, warn};

pub struct SqsConfig {
    pub queue_url: String,
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub topic_arn: Option<String>,
    pub events_path: PathBuf,
}

struct Endpoint {
    host: String,
    region: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}

fn parse_endpoint(queue_url: &str) -> Result<Endpoint> {
    let rest = queue_url.strip_prefix("https://").ok_or_else(|| anyhow!("queue url must be https"))?;
    let host = rest.split('/').next().unwrap_or("");
    // sqs.<region>.amazonaws.com
    let region = host
        .strip_prefix("sqs.")
        .and_then(|h| h.strip_suffix(".amazonaws.com"))
        .filter(|r| !r.is_empty() && !r.contains('.'))
        .ok_or_else(|| anyhow!("cannot determine region from queue url host '{host}'"))?;
    Ok(Endpoint { host: host.to_string(), region: region.to_string() })
}

struct Sqs {
    cfg: SqsConfig,
    ep: Endpoint,
    http: reqwest::Client,
}

impl Sqs {
    async fn call(&self, action: &str, body: &Value) -> Result<Value> {
        let body = body.to_string();
        let now = OffsetDateTime::now_utc();
        let amz_date = now.format(format_description!("[year][month][day]T[hour][minute][second]Z"))?;
        let date = &amz_date[..8];
        let target = format!("AmazonSQS.{action}");
        let ctype = "application/x-amz-json-1.0";

        // Canonical headers must be sorted by name.
        let mut headers = vec![
            ("content-type", ctype.to_string()),
            ("host", self.ep.host.clone()),
            ("x-amz-date", amz_date.clone()),
        ];
        if let Some(t) = &self.cfg.session_token {
            headers.push(("x-amz-security-token", t.clone()));
        }
        headers.push(("x-amz-target", target.clone()));
        let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let signed_headers = headers.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");

        let canonical = format!(
            "POST\n/\n\n{canonical_headers}\n{signed_headers}\n{}",
            hex(&Sha256::digest(body.as_bytes()))
        );
        let scope = format!("{date}/{}/sqs/aws4_request", self.ep.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let k = hmac(format!("AWS4{}", self.cfg.secret_key).as_bytes(), date);
        let k = hmac(&k, &self.ep.region);
        let k = hmac(&k, "sqs");
        let k = hmac(&k, "aws4_request");
        let signature = hex(&hmac(&k, &to_sign));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.cfg.access_key
        );

        let mut req = self
            .http
            .post(format!("https://{}/", self.ep.host))
            .header("content-type", ctype)
            .header("x-amz-date", &amz_date)
            .header("x-amz-target", &target)
            .header("authorization", auth);
        if let Some(t) = &self.cfg.session_token {
            req = req.header("x-amz-security-token", t);
        }
        let resp = req.body(body).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("SQS {action} failed: HTTP {status}: {}", text.chars().take(500).collect::<String>());
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text)?)
    }

    /// Handles one queue message body: an SNS envelope or a raw SES event.
    async fn handle_body(&self, lists: &Lists, body: &str) -> Result<()> {
        let v: Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(e) => {
                warn!("dropping non-JSON SQS message: {e}");
                return Ok(());
            }
        };
        match v.get("Type").and_then(Value::as_str) {
            Some("Notification") => {
                if let (Some(expected), Some(actual)) =
                    (&self.cfg.topic_arn, v.get("TopicArn").and_then(Value::as_str))
                {
                    if expected != actual {
                        warn!("dropping SQS message from unexpected topic {actual}");
                        return Ok(());
                    }
                }
                let msg = v.get("Message").and_then(Value::as_str).unwrap_or("");
                process_ses_event(lists, &self.cfg.events_path, msg).await
            }
            Some(other) => {
                info!("ignoring SNS message of type {other}");
                Ok(())
            }
            // Raw message delivery enabled on the subscription.
            None => process_ses_event(lists, &self.cfg.events_path, body).await,
        }
    }

    async fn poll_once(&self, lists: &Lists) -> Result<usize> {
        let out = self
            .call(
                "ReceiveMessage",
                &json!({
                    "QueueUrl": self.cfg.queue_url,
                    "MaxNumberOfMessages": 10,
                    "WaitTimeSeconds": 20,
                }),
            )
            .await?;
        let msgs = out.get("Messages").and_then(Value::as_array).cloned().unwrap_or_default();
        for m in &msgs {
            let body = m.get("Body").and_then(Value::as_str).unwrap_or("");
            let Some(handle) = m.get("ReceiptHandle").and_then(Value::as_str) else { continue };
            match self.handle_body(lists, body).await {
                Ok(()) => {
                    self.call("DeleteMessage", &json!({"QueueUrl": self.cfg.queue_url, "ReceiptHandle": handle}))
                        .await
                        .context("cannot delete processed message")?;
                }
                // Left in the queue: it becomes visible again after the visibility timeout.
                Err(e) => warn!("cannot process SQS message: {e:#}"),
            }
        }
        Ok(msgs.len())
    }
}

pub async fn run(cfg: SqsConfig, lists: Arc<Lists>) -> Result<()> {
    let ep = parse_endpoint(&cfg.queue_url)?;
    info!("polling SQS queue {} (region {})", cfg.queue_url, ep.region);
    let sqs = Sqs { cfg, ep, http: reqwest::Client::builder().timeout(Duration::from_secs(40)).build()? };
    let mut backoff = Duration::from_secs(1);
    loop {
        match sqs.poll_once(&lists).await {
            Ok(_) => backoff = Duration::from_secs(1),
            Err(e) => {
                warn!("SQS poll failed: {e:#} (retry in {}s)", backoff.as_secs());
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}
