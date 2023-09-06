use ed25519_dalek::PublicKey;
use std::{error::Error, fmt};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::network::crypto::PublicKeyBytes;

pub type PeerPort = u64;
#[derive(Debug, Clone)]
pub struct AddrParseError;

// Implement Display and Error for AddrParseError
impl fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse Addr")
    }
}

impl std::error::Error for AddrParseError {}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Addr(pub PublicKeyBytes);

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl Addr {
    pub fn network(&self) -> &'static str {
        "ed25519.PublicKey"
    }
}

impl std::str::FromStr for Addr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| AddrParseError)?;
        PublicKey::from_bytes(&bytes)
            .map(|pk| Addr(PublicKeyBytes(pk.to_bytes())))
            .map_err(|_| AddrParseError)
    }
}

impl From<PublicKey> for Addr {
    fn from(pk: PublicKey) -> Self {
        Addr(PublicKeyBytes(pk.to_bytes()))
    }
}

impl From<Addr> for PublicKeyBytes {
    fn from(val: Addr) -> Self {
        val.0
    }
}

#[derive(Debug)]
pub enum IrwdError {
    Network,
}

impl fmt::Display for IrwdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "irwd error")
    }
}
impl Error for IrwdError {}

pub trait Conn:
    AsyncRead + AsyncWrite + std::marker::Unpin + Send + Sync + std::fmt::Debug
{
    fn peer_addr(&self) -> Result<String, IrwdError>;
    fn local_addr(&self) -> Result<String, IrwdError>;
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn AsyncRead + Unpin + Send + Sync>,
        Box<dyn AsyncWrite + Unpin + Send + Sync>,
    );
}

impl Conn for TcpStream {
    fn peer_addr(&self) -> Result<String, IrwdError> {
        Ok(self
            .peer_addr()
            .map_err(|_| IrwdError::Network)?
            .to_string())
    }

    fn local_addr(&self) -> Result<String, IrwdError> {
        Ok(self
            .local_addr()
            .map_err(|_| IrwdError::Network)?
            .to_string())
    }
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn AsyncRead + Unpin + Send + Sync>,
        Box<dyn AsyncWrite + Unpin + Send + Sync>,
    ) {
        let (r, w) = tokio::io::split(self);
        (Box::new(r), Box::new(w))
    }
}
