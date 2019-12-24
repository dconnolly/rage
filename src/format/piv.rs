use ring::{
    agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256},
    rand::SystemRandom,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

use crate::{
    error::Error,
    keys::{piv_to_str, FileKey},
    primitives::{aead_encrypt, hkdf, p256::PublicKey},
};

#[cfg(feature = "yubikey")]
pub mod yubikey;

const PIV_RECIPIENT_TAG: &[u8] = b"piv ";
const PIV_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/piv";

pub(crate) fn piv_tag(pk: &PublicKey) -> [u8; 4] {
    let tag = Sha256::digest(piv_to_str(pk).as_bytes());
    (&tag[0..4]).try_into().expect("length is correct")
}

#[derive(Debug)]
pub(crate) struct RecipientLine {
    tag: [u8; 4],
    epk: PublicKey,
    encrypted_file_key: [u8; 32],
}

impl RecipientLine {
    pub(crate) fn wrap_file_key(file_key: &FileKey, pk: &PublicKey) -> Self {
        let rng = SystemRandom::new();

        let esk = EphemeralPrivateKey::generate(&ECDH_P256, &rng).expect("TODO handle failing RNG");
        let epk = PublicKey::from_bytes(esk.compute_public_key().expect("TODO").as_ref())
            .expect("epk is valid");

        let pk_uncompressed = pk.decompress();
        let pk_ring = UnparsedPublicKey::new(&ECDH_P256, pk_uncompressed.as_bytes());

        let enc_key = agree_ephemeral(esk, &pk_ring, Error::DecryptionFailed, |shared_secret| {
            let mut salt = vec![];
            salt.extend_from_slice(epk.as_bytes());
            salt.extend_from_slice(pk.as_bytes());

            Ok(hkdf(&salt, PIV_RECIPIENT_KEY_LABEL, shared_secret))
        })
        .expect("keys are correct");

        let encrypted_file_key = {
            let mut key = [0; 32];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.0.expose_secret()));
            key
        };

        RecipientLine {
            tag: piv_tag(pk),
            epk,
            encrypted_file_key,
        }
        .into()
    }
}

pub(super) mod read {
    use nom::{
        bytes::streaming::{tag, take},
        combinator::{map, map_opt, map_res},
        sequence::{preceded, separated_pair},
        IResult,
    };

    use super::*;
    use crate::util::read::encoded_data;

    fn piv_tag(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
        encoded_data(4, [0; 4])(input)
    }

    fn epk(input: &[u8]) -> IResult<&[u8], PublicKey> {
        map_opt(
            map_res(take(44usize), |encoded| {
                base64::decode_config(encoded, base64::URL_SAFE_NO_PAD)
            }),
            |bytes| PublicKey::from_bytes(&bytes),
        )(input)
    }

    pub(crate) fn recipient_line<'a, N>(
        line_ending: &'a impl Fn(&'a [u8]) -> IResult<&'a [u8], N>,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], RecipientLine> {
        move |input: &[u8]| {
            preceded(
                tag(PIV_RECIPIENT_TAG),
                map(
                    separated_pair(
                        separated_pair(piv_tag, tag(" "), epk),
                        line_ending,
                        encoded_data(32, [0; 32]),
                    ),
                    |((tag, epk), encrypted_file_key)| RecipientLine {
                        tag,
                        epk,
                        encrypted_file_key,
                    },
                ),
            )(input)
        }
    }
}

pub(super) mod write {
    use cookie_factory::{
        combinator::{slice, string},
        sequence::tuple,
        SerializeFn,
    };
    use std::io::Write;

    use super::*;
    use crate::util::write::encoded_data;

    pub(crate) fn recipient_line<'a, W: 'a + Write>(
        r: &RecipientLine,
        line_ending: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(PIV_RECIPIENT_TAG),
            encoded_data(&r.tag),
            string(" "),
            encoded_data(r.epk.as_bytes()),
            string(line_ending),
            encoded_data(&r.encrypted_file_key),
        ))
    }
}
