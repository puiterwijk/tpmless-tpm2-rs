use std::str::FromStr;

use openssl::hash::MessageDigest;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid PCR number requested")]
    InvalidPCR,
    #[error("Unused algorithm requested")]
    UnusedAlgo,
    #[error("Cryptographic error occured")]
    Crypto(#[from] openssl::error::ErrorStack),
    #[error("Invalid parameter size")]
    InvalidSize,
    #[error("Unsupported algorithm requested")]
    UnsupportedAlgo,
}

#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    fn new_empty(&self) -> Vec<u8> {
        let len = self.openssl_md().size();
        vec![0; len]
    }

    fn openssl_md(&self) -> MessageDigest {
        match self {
            DigestAlgorithm::Sha1 => MessageDigest::sha1(),
            DigestAlgorithm::Sha256 => MessageDigest::sha256(),
            DigestAlgorithm::Sha384 => MessageDigest::sha384(),
            DigestAlgorithm::Sha512 => MessageDigest::sha512(),
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
