use std::collections::HashMap;

use openssl::hash::Hasher;

use crate::{DigestAlgorithm, Error};

type PcrNum = u32;

#[derive(Default, Debug)]
pub struct PcrExtender {
    banks: HashMap<DigestAlgorithm, Vec<Vec<u8>>>,
}

fn extend_bank_val(
    pcr_index: usize,
    algo: DigestAlgorithm,
    digest: &[u8],
    bank: &mut Vec<Vec<u8>>,
) -> Result<(), Error> {
    let mut hasher = Hasher::new(algo.openssl_md())?;
    hasher.update(&bank[pcr_index])?;
    hasher.update(digest)?;
    bank[pcr_index] = hasher.finish()?.to_vec();
    Ok(())
}

impl PcrExtender {
    pub fn extend_digest(
        &mut self,
        pcr_index: PcrNum,
        algo: DigestAlgorithm,
        digest: &[u8],
    ) -> Result<(), Error> {
        let pcr_index = pcr_index as usize;

        if digest.len() != algo.openssl_md().size() {
            return Err(Error::InvalidSize);
        }

        let bank = self.banks.get_mut(&algo).ok_or(Error::UnusedAlgo)?;
        if pcr_index < bank.len() {
            extend_bank_val(pcr_index, algo, digest, bank)?;
        }

        Ok(())
    }

    pub fn extend(&mut self, pcr_index: PcrNum, value: &[u8]) -> Result<(), Error> {
        let pcr_index = pcr_index as usize;

        for (algo, bank) in self.banks.iter_mut() {
            let mut hasher = Hasher::new(algo.openssl_md())?;
            hasher.update(value)?;
            let new_val = hasher.finish()?;

            extend_bank_val(pcr_index, *algo, &new_val, bank)?;
        }
        Ok(())
    }

    pub fn pcr_algo_value(&self, pcr_index: PcrNum, algo: DigestAlgorithm) -> Result<&[u8], Error> {
        let pcr_index = pcr_index as usize;

        let bank = self.banks.get(&algo).ok_or(Error::UnusedAlgo)?;
        if pcr_index >= bank.len() {
            return Err(Error::InvalidPCR);
        }
        Ok(&bank[pcr_index])
    }
}

#[derive(Default, Debug)]
pub struct PcrExtenderBuilder {
    num_pcrs: PcrNum,
    mds: Vec<DigestAlgorithm>,
}

impl PcrExtenderBuilder {
    pub fn new() -> Self {
        PcrExtenderBuilder {
            num_pcrs: 24,
            mds: Vec::new(),
        }
    }

    pub fn set_num_pcrs(&mut self, val: PcrNum) -> &mut Self {
        self.num_pcrs = val;
        self
    }

    pub fn add_digest_method(&mut self, md: DigestAlgorithm) -> &mut Self {
        self.mds.push(md);
        self
    }

    fn build_bank(&self, algo: &DigestAlgorithm) -> Vec<Vec<u8>> {
        let mut bank = Vec::new();

        for _ in 0..self.num_pcrs {
            bank.push(algo.new_empty());
        }

        bank
    }

    pub fn build(&self) -> PcrExtender {
        let mut banks = HashMap::new();
        for algo in &self.mds {
            banks.insert(*algo, self.build_bank(algo));
        }
        PcrExtender { banks }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_sha1_invalid_digest() {
        let mut extender = PcrExtenderBuilder::new()
            .set_num_pcrs(24)
            .add_digest_method(DigestAlgorithm::Sha1)
            .add_digest_method(DigestAlgorithm::Sha256)
            .build();

        extender
            .extend_digest(0, DigestAlgorithm::Sha1, &hex::decode("deadbeef").unwrap())
            .unwrap_err();
    }

    #[test]
    fn test_digest_sha1() {
        let mut extender = PcrExtenderBuilder::new()
            .set_num_pcrs(24)
            .add_digest_method(DigestAlgorithm::Sha1)
            .add_digest_method(DigestAlgorithm::Sha256)
            .build();

        extender
            .extend_digest(
                0,
                DigestAlgorithm::Sha1,
                &hex::decode("f1d2d2f924e986ac86fdf7b36c94bcdf32beec15").unwrap(),
            )
            .unwrap();

        assert_eq!(
            extender.pcr_algo_value(0, DigestAlgorithm::Sha1).unwrap(),
            &hex::decode("3D96EFE6E4A9ECB1270DF4D80DEDD5062B831B5A").unwrap(),
        );
        assert_eq!(
            extender.pcr_algo_value(10, DigestAlgorithm::Sha1).unwrap(),
            &[0; 20],
        );
        assert_eq!(
            extender.pcr_algo_value(0, DigestAlgorithm::Sha256).unwrap(),
            &[0; 32],
        );
        assert_eq!(
            extender
                .pcr_algo_value(10, DigestAlgorithm::Sha256)
                .unwrap(),
            &[0; 32],
        );
    }

    #[test]
    fn test_data() {
        let mut extender = PcrExtenderBuilder::new()
            .set_num_pcrs(24)
            .add_digest_method(DigestAlgorithm::Sha1)
            .add_digest_method(DigestAlgorithm::Sha256)
            .build();

        extender.extend(0, &"testing 42".as_bytes()).unwrap();

        assert_eq!(
            extender.pcr_algo_value(0, DigestAlgorithm::Sha1).unwrap(),
            &hex::decode("B2BC0096E981EBEF006DA20BBDD3F0BEC757BDD4").unwrap(),
        );
        assert_eq!(
            extender.pcr_algo_value(10, DigestAlgorithm::Sha1).unwrap(),
            &[0; 20],
        );
        assert_eq!(
            extender.pcr_algo_value(0, DigestAlgorithm::Sha256).unwrap(),
            &hex::decode("F11F5E30B2297E43A6AC98E9E0B0A94069B5074E0C1B021C77FC571872473BCD")
                .unwrap(),
        );
        assert_eq!(
            extender
                .pcr_algo_value(10, DigestAlgorithm::Sha256)
                .unwrap(),
            &[0; 32],
        );
    }

    #[test]
    fn test_digest_sha1_twice() {
        let mut extender = PcrExtenderBuilder::new()
            .set_num_pcrs(24)
            .add_digest_method(DigestAlgorithm::Sha1)
            .add_digest_method(DigestAlgorithm::Sha256)
            .build();

        extender
            .extend_digest(
                0,
                DigestAlgorithm::Sha1,
                &hex::decode("f1d2d2f924e986ac86fdf7b36c94bcdf32beec15").unwrap(),
            )
            .unwrap();
        extender
            .extend_digest(
                0,
                DigestAlgorithm::Sha1,
                &hex::decode("f1d2d2f924e986ac86fdf7b36c94bcdf32beec15").unwrap(),
            )
            .unwrap();

        assert_eq!(
            extender.pcr_algo_value(0, DigestAlgorithm::Sha1).unwrap(),
            &hex::decode("F804A5AC9D182856C86FF6FD33A7A07BFFB7CD27").unwrap(),
        );
    }

    #[test]
    fn test_multibank() {
        let mut extender = PcrExtenderBuilder::new()
            .set_num_pcrs(24)
            .add_digest_method(DigestAlgorithm::Sha1)
            .add_digest_method(DigestAlgorithm::Sha256)
            .build();

        extender
            .extend_digest(
                0,
                DigestAlgorithm::Sha1,
                &hex::decode("f1d2d2f924e986ac86fdf7b36c94bcdf32beec15").unwrap(),
            )
            .unwrap();
        extender
            .extend_digest(
                0,
                DigestAlgorithm::Sha256,
                &hex::decode("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(
            extender.pcr_algo_value(0, DigestAlgorithm::Sha1).unwrap(),
            &hex::decode("3D96EFE6E4A9ECB1270DF4D80DEDD5062B831B5A").unwrap(),
        );
        assert_eq!(
            extender.pcr_algo_value(0, DigestAlgorithm::Sha256).unwrap(),
            &hex::decode("44F12027AB81DFB6E096018F5A9F19645F988D45529CDED3427159DC0032D921")
                .unwrap(),
        );
    }
}
