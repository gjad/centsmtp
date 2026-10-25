//! Custom encrypted tunnel between `centsmtp_client` and `centsmtp_server`.
//!
//! Handshake (pre-shared key `psk`):
//!   client -> server : MAGIC | client_nonce(32)
//!   server -> client : server_nonce(32)
//!   keys             : HKDF-SHA256(salt = client_nonce || server_nonce, ikm = psk)
//!                      -> independent ChaCha20-Poly1305 keys for each direction
//!   client -> server : encrypted hello frame   (proves the client knows the key)
//!   server -> client : encrypted hello frame   (proves the server knows the key)
//!
//! Frame: u32 big-endian ciphertext length | ciphertext (payload + 16 byte tag).
//! The length is authenticated as AAD, the nonce is a per-direction counter,
//! and fresh random nonces per connection make every session key unique.

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

const MAGIC: &[u8; 8] = b"CENTSMP1";
const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HELLO_LIMIT: usize = 256;
const HELLO_CLIENT: &[u8] = b"centsmtp-hello-client";
const HELLO_SERVER: &[u8] = b"centsmtp-hello-server";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum size of a raw mail message accepted by the bridge.
pub const MAX_MESSAGE_SIZE: usize = 30 * 1024 * 1024;
const MAX_FRAME: usize = MAX_MESSAGE_SIZE + 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct MailRequest {
    /// Name of the client instance (used for archive directories).
    pub client_name: String,
    /// Envelope sender; empty string means the null sender `<>`.
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    /// Raw RFC 5322 message, CRLF line endings, dot-unstuffed.
    pub data: Vec<u8>,
}

/// Outcome of a request (overall) or of a single recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    /// Accepted by the relay (SES).
    Sent,
    /// Sender or recipient address is syntactically invalid.
    InvalidAddress,
    /// Recipient domain has no mail server (no MX / A record).
    InvalidDomain,
    /// Recipient domain could not be verified right now (DNS failure); retry later.
    DomainCheckFailed,
    /// Recipient is on the blacklist (previous permanent bounce / complaint).
    Blacklisted,
    TooLarge,
    /// Relay (SES) permanently rejected the message.
    RelayRejected,
    /// Relay (SES) temporarily failed; retry later.
    RelayTemporary,
    Internal,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Sent => "SENT",
            Status::InvalidAddress => "INVALID_ADDRESS",
            Status::InvalidDomain => "INVALID_DOMAIN",
            Status::DomainCheckFailed => "DOMAIN_CHECK_FAILED",
            Status::Blacklisted => "BLACKLISTED",
            Status::TooLarge => "TOO_LARGE",
            Status::RelayRejected => "RELAY_REJECTED",
            Status::RelayTemporary => "RELAY_TEMPORARY",
            Status::Internal => "INTERNAL_ERROR",
        }
    }

    /// Whether the sender may succeed by retrying later.
    pub fn is_temporary(self) -> bool {
        matches!(self, Status::DomainCheckFailed | Status::RelayTemporary | Status::Internal)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RcptResult {
    pub addr: String,
    pub status: Status,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MailResponse {
    /// Server side mail id (also part of the archive file name).
    pub id: String,
    /// `Sent` when at least one recipient was handed to the relay, otherwise the first failure.
    pub status: Status,
    /// Human readable summary.
    pub message: String,
    pub rcpts: Vec<RcptResult>,
}

/// Generate a random 256-bit key encoded as hex.
pub fn generate_key() -> String {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k.iter().map(|b| format!("{b:02x}")).collect()
}

fn derive_keys(psk: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> (ChaCha20Poly1305, ChaCha20Poly1305) {
    let mut salt = Vec::with_capacity(client_nonce.len() + server_nonce.len());
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);
    let hk = Hkdf::<Sha256>::new(Some(&salt), psk);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"centsmtp c2s", &mut c2s).expect("valid length");
    hk.expand(b"centsmtp s2c", &mut s2c).expect("valid length");
    (
        ChaCha20Poly1305::new(Key::from_slice(&c2s)),
        ChaCha20Poly1305::new(Key::from_slice(&s2c)),
    )
}

fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::clone_from_slice(&n)
}

pub struct SecureChannel<S> {
    stream: S,
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_ctr: u64,
    rx_ctr: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecureChannel<S> {
    /// Client side of the handshake.
    pub async fn connect(mut stream: S, psk: &[u8]) -> Result<Self> {
        let mut cn = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut cn);
        let mut sn = [0u8; NONCE_LEN];

        timeout(HANDSHAKE_TIMEOUT, async {
            stream.write_all(MAGIC).await?;
            stream.write_all(&cn).await?;
            stream.flush().await?;
            stream.read_exact(&mut sn).await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| anyhow!("handshake timed out"))??;

        let (c2s, s2c) = derive_keys(psk, &cn, &sn);
        let mut ch = Self { stream, tx: c2s, rx: s2c, tx_ctr: 0, rx_ctr: 0 };

        timeout(HANDSHAKE_TIMEOUT, async {
            ch.send(HELLO_CLIENT).await?;
            let reply = ch.recv_limited(HELLO_LIMIT).await?;
            if reply != HELLO_SERVER {
                bail!("unexpected server hello");
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow!("handshake timed out"))??;
        Ok(ch)
    }

    /// Server side of the handshake.
    pub async fn accept(mut stream: S, psk: &[u8]) -> Result<Self> {
        let mut magic = [0u8; 8];
        let mut cn = [0u8; NONCE_LEN];
        let mut sn = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut sn);

        timeout(HANDSHAKE_TIMEOUT, async {
            stream.read_exact(&mut magic).await?;
            stream.read_exact(&mut cn).await?;
            if &magic != MAGIC {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad magic"));
            }
            stream.write_all(&sn).await?;
            stream.flush().await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| anyhow!("handshake timed out"))??;

        let (c2s, s2c) = derive_keys(psk, &cn, &sn);
        let mut ch = Self { stream, tx: s2c, rx: c2s, tx_ctr: 0, rx_ctr: 0 };

        timeout(HANDSHAKE_TIMEOUT, async {
            let hello = ch.recv_limited(HELLO_LIMIT).await?;
            if hello != HELLO_CLIENT {
                bail!("unexpected client hello");
            }
            ch.send(HELLO_SERVER).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow!("handshake timed out"))??;
        Ok(ch)
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_FRAME {
            bail!("frame too large");
        }
        let len_bytes = ((data.len() + TAG_LEN) as u32).to_be_bytes();
        let ct = self
            .tx
            .encrypt(&nonce(self.tx_ctr), Payload { msg: data, aad: &len_bytes })
            .map_err(|_| anyhow!("encryption failed"))?;
        self.tx_ctr += 1;
        self.stream.write_all(&len_bytes).await?;
        self.stream.write_all(&ct).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        self.recv_limited(MAX_FRAME).await
    }

    async fn recv_limited(&mut self, limit: usize) -> Result<Vec<u8>> {
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len < TAG_LEN || len > limit + TAG_LEN {
            bail!("invalid frame length");
        }
        let mut ct = vec![0u8; len];
        self.stream.read_exact(&mut ct).await?;
        let pt = self
            .rx
            .decrypt(&nonce(self.rx_ctr), Payload { msg: &ct, aad: &len_bytes })
            .map_err(|_| anyhow!("authentication failed (wrong key or tampered data)"))?;
        self.rx_ctr += 1;
        Ok(pt)
    }
}
