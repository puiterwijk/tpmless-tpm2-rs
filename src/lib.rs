use std::str::FromStr;

use openssl::hash::MessageDigest;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid PCR number requested")]
    InvalidPcr,
    #[error("Unused algorithm requested")]
    UnusedAlgo,
    #[error("Cryptographic error occured")]
    Crypto(#[from] openssl::error::ErrorStack),
    #[error("Invalid parameter size")]
    InvalidSize,
    #[error("Unsupported algorithm requested")]
    UnsupportedAlgo,
    #[error("I/O Error")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone, PartialOrd, Ord)]
#[non_exhaustive]
#[cfg_attr(any(feature = "serialize", test), derive(serde::Serialize))]
#[cfg_attr(any(feature = "serialize", test), serde(rename_all = "lowercase"))]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub fn openssl_md(&self) -> MessageDigest {
        match self {
            DigestAlgorithm::Sha1 => MessageDigest::sha1(),
            DigestAlgorithm::Sha256 => MessageDigest::sha256(),
            DigestAlgorithm::Sha384 => MessageDigest::sha384(),
            DigestAlgorithm::Sha512 => MessageDigest::sha512(),
        }
    }

    pub fn from_tpm_alg_id(alg_id: u16) -> Option<Self> {
        match alg_id {
            0x0004 => Some(DigestAlgorithm::Sha1),
            0x000B => Some(DigestAlgorithm::Sha256),
            0x000C => Some(DigestAlgorithm::Sha384),
            0x000D => Some(DigestAlgorithm::Sha512),
            _ => None,
        }
    }
}

impl FromStr for DigestAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let s = s.to_lowercase();
        match &s[..] {
            "sha1" => Ok(DigestAlgorithm::Sha1),
            "sha256" => Ok(DigestAlgorithm::Sha256),
            "sha384" => Ok(DigestAlgorithm::Sha384),
            "sha512" => Ok(DigestAlgorithm::Sha512),
            _ => Err(Error::UnsupportedAlgo),
        }
    }
}

mod pcrs;
pub use pcrs::{PcrExtender, PcrExtenderBuilder};

mod objects;

mod crypto;
mod credentials;
