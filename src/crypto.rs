use openssl::hash::MessageDigest;
use openssl_kdf::{Kdf, KdfKbMode, KdfMacType, KdfType};

use crate::Error;

#[cfg(feature = "backported_kdf")]
pub(crate) fn kdf_a<KT: AsRef<[u8]>, LT: AsRef<[u8]>, CUT: AsRef<[u8]>, CVT: AsRef<[u8]>>(
    md: MessageDigest,
    key: KT,
    label: LT,
    contextU: CUT,
    contextV: CVT,
    bits: u32,
) -> Result<Vec<u8>, Error> {
    let mut context: Vec<u8> =
        Vec::with_capacity(contextU.as_ref().len() + contextV.as_ref().len() - 4);
    context.extend_from_slice(&contextU.as_ref()[2..]);
    context.extend_from_slice(&contextV.as_ref()[2..]);
    let context = context;

    let kdf = Kdf::new(KdfType::KeyBased)?;
    kdf.set_kb_mode(KdfKbMode::Counter)?;
    kdf.set_kb_mac_type(KdfMacType::Hmac)?;
    kdf.set_digest(md)?;
    kdf.set_salt(label.as_ref())?;
    kdf.set_kb_info(&context)?;
    kdf.set_key(key.as_ref())?;

    Ok(kdf.derive((bits / 8) as usize)?)
}
