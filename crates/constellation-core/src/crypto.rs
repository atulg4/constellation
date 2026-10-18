//! Payload encryption and hashing. No primitive is implemented here.
//!
//! Suite 1 is HPKE base mode (RFC 9180) with DHKEM(X25519, HKDF-SHA256),
//! HKDF-SHA256, and ChaCha20-Poly1305, from the `hpke` crate. The AAD binds
//! the ciphertext to the creator device and audience so a carrier cannot
//! re-wrap it under a different envelope. Carriers verify the envelope's
//! SHA-256 commitment to the ciphertext and never hold a decryption key.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};

use crate::domain;
use crate::envelope::{Audience, Envelope};
use crate::identity::{hpke_public, DeviceId, DeviceIdentity, EncryptionKey};

fixed_bytes!(
    /// A SHA-256 digest.
    Hash,
    32
);

/// The only encryption suite this profile accepts.
pub const SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305: u16 = 1;

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type KemType = X25519HkdfSha256;

/// Errors from sealing or opening payloads.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Recipient or encapsulated key did not parse.
    #[error("invalid key material")]
    InvalidKey,
    /// Encryption failed.
    #[error("seal failed")]
    Seal,
    /// Decryption or authentication failed.
    #[error("open failed")]
    Open,
    /// The envelope names a suite this build does not implement.
    #[error("unsupported encryption suite")]
    UnsupportedSuite,
    /// The envelope's audience is not this device.
    #[error("object is not addressed to this device")]
    NotAddressedToDevice,
}

/// SHA-256 over the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    Hash(hasher.finalize().into())
}

/// AAD that ties a ciphertext to its creator device and intended audience.
pub fn payload_aad(creator: &DeviceId, audience: &Audience) -> Vec<u8> {
    let mut aad = domain::PAYLOAD_AAD.to_vec();
    aad.extend_from_slice(&creator.0);
    aad.extend_from_slice(&audience.user.0);
    aad.extend_from_slice(&audience.device.0);
    aad
}

/// Seals `plaintext` to `recipient`. Returns the encapsulated key and ciphertext.
pub(crate) fn seal(
    recipient: &EncryptionKey,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<(EncryptionKey, Vec<u8>), CryptoError> {
    let public = hpke_public(recipient).map_err(|_| CryptoError::InvalidKey)?;
    let (encapped, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, KemType>(
        &OpModeS::Base,
        &public,
        domain::PAYLOAD_INFO,
        plaintext,
        aad,
        rng,
    )
    .map_err(|_| CryptoError::Seal)?;
    let mut enc = [0u8; 32];
    encapped.write_exact(&mut enc);
    Ok((EncryptionKey(enc), ciphertext))
}

/// Opens `ciphertext` with the device's private key.
pub(crate) fn open(
    device: &DeviceIdentity,
    encapsulated: &EncryptionKey,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let encapped = <KemType as Kem>::EncappedKey::from_bytes(&encapsulated.0)
        .map_err(|_| CryptoError::InvalidKey)?;
    hpke::single_shot_open::<Aead, Kdf, KemType>(
        &OpModeR::Base,
        device.decryption_key(),
        &encapped,
        domain::PAYLOAD_INFO,
        ciphertext,
        aad,
    )
    .map_err(|_| CryptoError::Open)
}

/// Decrypts an object's payload for `device`, if the envelope is addressed to it.
///
/// This does not verify the envelope signature or hash; callers run the full
/// validation pipeline in [`crate::node`] first. It exists so tests and
/// applications can prove that only the audience device can read a payload.
pub fn open_payload(
    device: &DeviceIdentity,
    envelope: &Envelope,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let body = &envelope.body;
    if body.encryption.suite != SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305 {
        return Err(CryptoError::UnsupportedSuite);
    }
    if body.audience.device != device.id() {
        return Err(CryptoError::NotAddressedToDevice);
    }
    let aad = payload_aad(&body.creator.body.device, &body.audience);
    open(device, &body.encryption.encapsulated_key, &aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::UserIdentity;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn device(seed: u8) -> DeviceIdentity {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let user = UserIdentity::generate(&mut rng);
        DeviceIdentity::generate(&user, 0, &mut rng)
    }

    #[test]
    fn seal_then_open_round_trips_only_for_recipient() {
        let recipient = device(1);
        let other = device(2);
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let (enc, ct) =
            seal(&recipient.encryption_key(), b"aad", b"hello", &mut rng).expect("seal");
        assert_ne!(ct, b"hello");
        assert_eq!(ct.len(), 5 + crate::AEAD_TAG_BYTES);
        assert_eq!(open(&recipient, &enc, b"aad", &ct).expect("open"), b"hello");
        assert_eq!(open(&other, &enc, b"aad", &ct), Err(CryptoError::Open));
        assert_eq!(
            open(&recipient, &enc, b"other-aad", &ct),
            Err(CryptoError::Open)
        );
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert_eq!(
            open(&recipient, &enc, b"aad", &tampered),
            Err(CryptoError::Open)
        );
    }

    #[test]
    fn sealing_is_randomized_per_object() {
        let recipient = device(1);
        let mut rng = ChaCha20Rng::from_seed([4; 32]);
        let (enc1, ct1) = seal(&recipient.encryption_key(), b"", b"same", &mut rng).expect("seal");
        let (enc2, ct2) = seal(&recipient.encryption_key(), b"", b"same", &mut rng).expect("seal");
        assert_ne!(enc1, enc2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256("abc"), FIPS 180-4 example.
        let digest = sha256(&[b"a", b"bc"]);
        assert_eq!(digest.0[..4], [0xba, 0x78, 0x16, 0xbf],);
    }
}
