use std::io::{Read, Write};
use std::convert::TryFrom;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use openssl::pkey::{PKey, Public};

use crate::Error;

#[derive(Debug)]
pub struct Tpm2b (
    Vec<u8>,
);

impl Tpm2b {
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Tpm2b, Error> {
        let size = reader.read_u16::<BigEndian>()? as usize;
        let mut contents: Vec<u8> = vec![0; size];
        reader.read_exact(&mut contents)?;

        Ok(Tpm2b(contents))
    }

    pub fn to_writer<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        writer.write_u16::<BigEndian>(self.0.len() as u16)?;
        writer.write_all(&self.0)?;

        Ok(())
    }
}

pub struct Tpm2bPublic {

}

impl Tpm2bPublic {
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Tpm2bPublic, Error> {
        let tpmt_public = Tpm2b::from_reader(reader)?.0;

        todo!();
    }
}

impl TryFrom<Tpm2bPublic> for PKey<Public> {
    type Error = Error;

    fn try_from(tpmpub: Tpm2bPublic) -> Result<PKey<Public>, Error> {
        todo!();
    }
}
