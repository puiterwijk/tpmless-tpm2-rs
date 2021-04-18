use std::collections::BTreeMap;

use openssl::hash::Hasher;

use crate::{DigestAlgorithm, Error};

type PcrNum = u32;

#[derive(Debug)]
pub struct PcrValue {
    algo: DigestAlgorithm,
    value: Vec<u8>,
    ever_extended: bool,
}

#[cfg(any(feature = "serialize", test))]
impl serde::Serialize for PcrValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.value))
    }
}

impl PcrValue {
    fn extend(&mut self, digest: &[u8]) -> Result<(), Error> {
        let mut hasher = Hasher::new(self.algo.openssl_md())?;
        hasher.update(&self.value)?;
        hasher.update(digest)?;
        self.value = hasher.finish()?.to_vec();
        self.ever_extended = true;
        Ok(())
    }
}

impl DigestAlgorithm {
    fn new_empty(&self) -> PcrValue {
        let len = self.openssl_md().size();
        PcrValue {
            algo: *self,
            value: vec![0; len],
            ever_extended: false,
        }
    }
}

#[derive(Default, Debug)]
pub struct PcrExtender {
    banks: BTreeMap<DigestAlgorithm, Vec<PcrValue>>,
}

#[cfg(any(feature = "serialize", test))]
impl serde::Serialize for PcrExtender {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.banks.len()))?;
        for (algo, bank) in &self.banks {
            serde::ser::SerializeMap::serialize_entry(&mut map, &algo, &bank)?;
        }
        serde::ser::SerializeMap::end(map)
    }
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
            bank[pcr_index].extend(digest)?;
        }

        Ok(())
    }

    pub fn extend(&mut self, pcr_index: PcrNum, value: &[u8]) -> Result<(), Error> {
        let pcr_index = pcr_index as usize;

        for (algo, bank) in self.banks.iter_mut() {
            let mut hasher = Hasher::new(algo.openssl_md())?;
            hasher.update(value)?;
            let new_val = hasher.finish()?;

            bank[pcr_index].extend(&new_val)?;
        }
        Ok(())
    }

    pub fn pcr_algo_value(&self, pcr_index: PcrNum, algo: DigestAlgorithm) -> Result<&[u8], Error> {
        let pcr_index = pcr_index as usize;

        let bank = self.banks.get(&algo).ok_or(Error::UnusedAlgo)?;
        if pcr_index >= bank.len() {
            return Err(Error::InvalidPcr);
        }
        Ok(&bank[pcr_index].value)
    }

    pub fn values(&self) -> BTreeMap<DigestAlgorithm, Vec<Vec<u8>>> {
        self.banks
            .iter()
            .map(|(algo, bank)| (*algo, bank.iter().map(|val| val.value.clone()).collect()))
            .collect()
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

    pub fn build(&self) -> PcrExtender {
        let mut banks = BTreeMap::new();
        for algo in &self.mds {
            let mut bank = Vec::new();

            for _ in 0..self.num_pcrs {
                bank.push(algo.new_empty());
            }

            banks.insert(*algo, bank);
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

    #[test]
    fn test_multibank_all_values() {
        let mut extender = PcrExtenderBuilder::new()
            .set_num_pcrs(24)
            .add_digest_method(DigestAlgorithm::Sha1)
            .add_digest_method(DigestAlgorithm::Sha256)
            .build();

        extender
            .extend_digest(
                8,
                DigestAlgorithm::Sha1,
                &hex::decode("f1d2d2f924e986ac86fdf7b36c94bcdf32beec15").unwrap(),
            )
            .unwrap();
        extender
            .extend_digest(
                8,
                DigestAlgorithm::Sha256,
                &hex::decode("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")
                    .unwrap(),
            )
            .unwrap();

        let values = extender.values();

        assert_eq!(values.get(&DigestAlgorithm::Sha1).unwrap()[0], [0; 20],);
        assert_eq!(
            values.get(&DigestAlgorithm::Sha1).unwrap()[8],
            hex::decode("3D96EFE6E4A9ECB1270DF4D80DEDD5062B831B5A").unwrap(),
        );
        assert_eq!(values.get(&DigestAlgorithm::Sha1).unwrap()[10], [0; 20],);
        assert_eq!(values.get(&DigestAlgorithm::Sha256).unwrap()[0], [0; 32],);
        assert_eq!(
            values.get(&DigestAlgorithm::Sha256).unwrap()[8],
            hex::decode("44F12027AB81DFB6E096018F5A9F19645F988D45529CDED3427159DC0032D921")
                .unwrap(),
        );
        assert_eq!(values.get(&DigestAlgorithm::Sha256).unwrap()[10], [0; 32],);
    }

    #[test]
    fn test_multibank_serialize() {
        let mut extender = PcrExtenderBuilder::new()
            .set_num_pcrs(24)
            .add_digest_method(DigestAlgorithm::Sha1)
            .add_digest_method(DigestAlgorithm::Sha256)
            .build();

        extender
            .extend_digest(
                8,
                DigestAlgorithm::Sha1,
                &hex::decode("f1d2d2f924e986ac86fdf7b36c94bcdf32beec15").unwrap(),
            )
            .unwrap();
        extender
            .extend_digest(
                8,
                DigestAlgorithm::Sha256,
                &hex::decode("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")
                    .unwrap(),
            )
            .unwrap();

        let values = serde_json::to_string_pretty(&extender).unwrap();

        assert!(values.contains(
            r#"
  "sha1": [
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "3d96efe6e4a9ecb1270df4d80dedd5062b831b5a",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000"
  ],"#
        ));
        assert!(values.contains(
            r#"
  "sha256": [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "44f12027ab81dfb6e096018f5a9f19645f988d45529cded3427159dc0032d921",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000"
  ]"#,
        ));
    }
}
