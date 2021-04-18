use openssl::{
    encrypt::Encrypter,
    hash::MessageDigest,
    pkey::{HasPublic, Id as pkey_id, PKeyRef},
    rand::rand_bytes,
    rsa::Padding,
};

use crate::{crypto::kdf_a, Error};

const CREDENTIAL_LABEL_SYMKEY: &[u8] = b"STORAGE";
const CREDENTIAL_LABEL_IDENTITY: &[u8] = b"IDENTITY";
const CREDENTIAL_LABEL_INTEGRITY: &[u8] = b"INTEGRITY";

pub struct Credential {
    id_object: Vec<u8>,
    encrypted_secret: Vec<u8>,
}

fn build_seed_rsa<KT, LT>(
    encryption_pub: &PKeyRef<KT>,
    oaep_md: MessageDigest,
    label: LT,
) -> Result<(Vec<u8>, Vec<u8>), Error>
where
    KT: HasPublic,
    LT: AsRef<[u8]>,
{
    let mut encrypter = Encrypter::new(&encryption_pub)?;
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    encrypter.set_rsa_oaep_md(oaep_md)?;
    encrypter.set_rsa_mgf1_md(oaep_md)?;
    encrypter.set_rsa_oaep_label(label.as_ref())?;

    let mut seed = vec![0; oaep_md.size()];
    rand_bytes(&mut seed)?;

    let mut encrypted_seed = vec![0; encrypter.encrypt_len(&seed)?];
    encrypter.encrypt(&seed, &mut encrypted_seed)?;

    Ok((seed, encrypted_seed))
}

fn build_seed<KT, LT>(
    encryption_pub: &PKeyRef<KT>,
    oaep_md: MessageDigest,
    label: LT,
) -> Result<(Vec<u8>, Vec<u8>), Error>
where
    KT: HasPublic,
    LT: AsRef<[u8]>,
{
    let key_id = encryption_pub.id();

    if key_id == pkey_id::RSA {
        build_seed_rsa(encryption_pub, oaep_md, label)
    } else {
        todo!();
    }
}

pub fn make_credential<CVT, KT, ONT>(
    credential_value: CVT,
    encryption_namealg: MessageDigest,
    encryption_pub: &PKeyRef<KT>,
    object_name: ONT,
) -> Result<Credential, Error>
where
    CVT: AsRef<[u8]>,
    KT: HasPublic,
    ONT: AsRef<[u8]>,
{
    let (seed, encrypted_seed) = build_seed(
        encryption_pub,
        encryption_namealg,
        &CREDENTIAL_LABEL_IDENTITY,
    )?;

    let symkey = kdf_a(
        encryption_namealg,
        &seed,
        &CREDENTIAL_LABEL_SYMKEY,
        &object_name,
        &[],
        encryption_namealg.size() as u32,
    )?;
    let hmac_key = kdf_a(
        encryption_namealg,
        &seed,
        &CREDENTIAL_LABEL_INTEGRITY,
        &[],
        &[],
        encryption_namealg.size() as u32,
    )?;
    todo!();
}
