//! Recipient domain verification: the domain must have a mail server (MX, or A/AAAA fallback).

use anyhow::Result;
use hickory_resolver::TokioResolver;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::time::timeout;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const VALID_TTL: Duration = Duration::from_secs(3600);
const INVALID_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Clone)]
pub enum Verdict {
    Valid,
    /// The domain definitely cannot receive mail.
    Invalid(String),
    /// The check itself failed (DNS timeout/SERVFAIL); not cached.
    Unknown(String),
}

pub struct DomainChecker {
    resolver: TokioResolver,
    cache: Mutex<HashMap<String, (Instant, Verdict)>>,
}

fn well_formed(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

impl DomainChecker {
    pub fn new() -> Result<Self> {
        Ok(Self { resolver: TokioResolver::builder_tokio()?.build(), cache: Mutex::new(HashMap::new()) })
    }

    pub async fn check(&self, domain: &str) -> Verdict {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if !well_formed(&domain) {
            return Verdict::Invalid("malformed domain name".into());
        }
        if let Some((at, verdict)) = self.cache.lock().unwrap().get(&domain) {
            let ttl = if matches!(verdict, Verdict::Valid) { VALID_TTL } else { INVALID_TTL };
            if at.elapsed() < ttl {
                return verdict.clone();
            }
        }
        let verdict = self.lookup(&domain).await;
        if !matches!(verdict, Verdict::Unknown(_)) {
            self.cache.lock().unwrap().insert(domain, (Instant::now(), verdict.clone()));
        }
        verdict
    }

    async fn lookup(&self, domain: &str) -> Verdict {
        let name = format!("{domain}.");
        match timeout(LOOKUP_TIMEOUT, self.resolver.mx_lookup(name.clone())).await {
            Err(_) => return Verdict::Unknown("DNS lookup timed out".into()),
            Ok(Ok(mx)) => {
                // RFC 7505 "null MX" (a single "." exchange) means the domain accepts no mail.
                return if mx.iter().any(|m| !m.exchange().is_root()) {
                    Verdict::Valid
                } else {
                    Verdict::Invalid("domain does not accept mail (null MX)".into())
                };
            }
            Ok(Err(e)) if e.is_nx_domain() => return Verdict::Invalid("domain does not exist".into()),
            Ok(Err(e)) if e.is_no_records_found() => {}
            Ok(Err(e)) => return Verdict::Unknown(format!("DNS error: {e}")),
        }
        // No MX: RFC 5321 falls back to the domain's own address records.
        match timeout(LOOKUP_TIMEOUT, self.resolver.lookup_ip(name)).await {
            Err(_) => Verdict::Unknown("DNS lookup timed out".into()),
            Ok(Ok(_)) => Verdict::Valid,
            Ok(Err(e)) if e.is_nx_domain() || e.is_no_records_found() => {
                Verdict::Invalid("domain has no mail server (no MX/A record)".into())
            }
            Ok(Err(e)) => Verdict::Unknown(format!("DNS error: {e}")),
        }
    }
}
