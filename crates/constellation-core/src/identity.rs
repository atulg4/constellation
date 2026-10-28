//! Identities for Mission 001.
//!
//! A *user* is an Ed25519 root key. A *device* has its own Ed25519 signing
//! key plus an X25519 key for HPKE payload encryption, and is authorized by
//! a [`DeviceAuthorization`] signed with the user root key. Trust in a user
//! key is established out of band (QR, fingerprint, introduction) and
//! recorded in a [`ContactBook`]. These are static test-grade identities:
//! no rotation, revocation, or recovery exists yet (see Mission 002).

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, Serializable};
use minicbor::{Decode, Encode};
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::{domain, Timestamp};

fixed_bytes!(
    /// A user's root Ed25519 public key.
    UserId,
    32
);
fixed_bytes!(
    /// A device's Ed25519 public key.
    DeviceId,
    32
);
fixed_bytes!(
    /// An X25519 public key used as an HPKE recipient or encapsulated key.
    EncryptionKey,
    32
);
fixed_bytes!(
    /// An Ed25519 signature.
    Sig,
    64
);

/// Errors from identity verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    /// A public key did not decode as a valid curve point.
    #[error("invalid public key")]
    InvalidKey,
    /// A signature did not verify.
    #[error("signature verification failed")]
    BadSignature,
}

/// Signed statement by a user root key that a device key pair acts for it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AuthorizationBody {
    /// The authorizing user.
    #[n(0)]
    pub user: UserId,
    /// The authorized signing device.
    #[n(1)]
    pub device: DeviceId,
    /// The device's HPKE recipient key.
    #[n(2)]
    pub encryption_key: EncryptionKey,
    /// When the authorization was issued.
    #[n(3)]
    pub issued_at: Timestamp,
}

/// [`AuthorizationBody`] plus the user root signature over it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct DeviceAuthorization {
    /// Signed statement.
    #[n(0)]
    pub body: AuthorizationBody,
    /// Ed25519 signature by `body.user` over the domain-separated body.
    #[n(1)]
    pub signature: Sig,
}

impl DeviceAuthorization {
    fn signing_input(body: &AuthorizationBody) -> Vec<u8> {
        let mut input = domain::DEVICE_AUTHORIZATION.to_vec();
        input.extend(minicbor::to_vec(body).expect("encoding into Vec cannot fail"));
        input
    }

    /// Checks that `body.user` really signed this authorization.
    pub fn verify(&self) -> Result<(), IdentityError> {
        verify(
            &self.body.user.0,
            &Self::signing_input(&self.body),
            &self.signature,
        )
    }
}

/// The public, shareable description of a device: what a sender needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    /// Owning user.
    pub user: UserId,
    /// Device signing key.
    pub device: DeviceId,
    /// Device HPKE recipient key.
    pub encryption_key: EncryptionKey,
    /// Proof that `user` authorized `device`.
    pub authorization: DeviceAuthorization,
}

/// A user root key pair.
#[derive(Clone)]
pub struct UserIdentity {
    signing: SigningKey,
}

impl UserIdentity {
    /// Generates a fresh root key from `rng`.
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self { signing }
    }

    /// The public user id.
    pub fn id(&self) -> UserId {
        UserId(self.signing.verifying_key().to_bytes())
    }

    /// Signs a device authorization.
    pub fn authorize(
        &self,
        device: DeviceId,
        encryption_key: EncryptionKey,
        issued_at: Timestamp,
    ) -> DeviceAuthorization {
        let body = AuthorizationBody {
            user: self.id(),
            device,
            encryption_key,
            issued_at,
        };
        let signature = Sig(self
            .signing
            .sign(&DeviceAuthorization::signing_input(&body))
            .to_bytes());
        DeviceAuthorization { body, signature }
    }
}

impl core::fmt::Debug for UserIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "UserIdentity({:?})", self.id())
    }
}

/// A device's private material plus its public record.
#[derive(Clone)]
pub struct DeviceIdentity {
    signing: SigningKey,
    decryption: <X25519HkdfSha256 as Kem>::PrivateKey,
    record: DeviceRecord,
}

impl DeviceIdentity {
    /// Generates a device key pair and has `user` authorize it.
    pub fn generate(user: &UserIdentity, issued_at: Timestamp, rng: &mut impl CryptoRng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let (decryption, public) = X25519HkdfSha256::gen_keypair_with_rng(rng);
        let mut encryption_key = [0u8; 32];
        public.write_exact(&mut encryption_key);
        let device = DeviceId(signing.verifying_key().to_bytes());
        let authorization = user.authorize(device, EncryptionKey(encryption_key), issued_at);
        let record = DeviceRecord {
            user: user.id(),
            device,
            encryption_key: EncryptionKey(encryption_key),
            authorization,
        };
        Self {
            signing,
            decryption,
            record,
        }
    }

    /// The public record a sender needs.
    pub fn record(&self) -> DeviceRecord {
        self.record.clone()
    }

    /// Device id.
    pub fn id(&self) -> DeviceId {
        self.record.device
    }

    /// Owning user id.
    pub fn user(&self) -> UserId {
        self.record.user
    }

    /// Public HPKE recipient key.
    pub fn encryption_key(&self) -> EncryptionKey {
        self.record.encryption_key
    }

    /// Signs `message` with the device key. Callers must domain-separate.
    pub(crate) fn sign(&self, message: &[u8]) -> Sig {
        Sig(self.signing.sign(message).to_bytes())
    }

    /// The HPKE private key, for payload opening only.
    pub(crate) fn decryption_key(&self) -> &<X25519HkdfSha256 as Kem>::PrivateKey {
        &self.decryption
    }

    /// Secret-derived, node-local salt for peer pseudonyms. Never leaves the node.
    pub(crate) fn local_salt(&self) -> [u8; 32] {
        let secret = self.signing.to_bytes();
        let digest = crate::crypto::sha256(&[domain::PEER_TAG, &secret]);
        digest.0
    }
}

impl core::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DeviceIdentity({:?})", self.record.device)
    }
}

/// Verifies an Ed25519 signature by raw public key bytes (strict mode).
pub(crate) fn verify(
    public: &[u8; 32],
    message: &[u8],
    signature: &Sig,
) -> Result<(), IdentityError> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| IdentityError::InvalidKey)?;
    key.verify_strict(message, &Signature::from_bytes(&signature.0))
        .map_err(|_| IdentityError::BadSignature)
}

/// Parses an HPKE public key from an [`EncryptionKey`].
pub(crate) fn hpke_public(
    key: &EncryptionKey,
) -> Result<<X25519HkdfSha256 as Kem>::PublicKey, IdentityError> {
    <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&key.0).map_err(|_| IdentityError::InvalidKey)
}

/// Which user root keys this node trusts, as verified out of band.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContactBook {
    trusted: BTreeSet<UserId>,
}

impl ContactBook {
    /// An empty book: trusts nobody.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `user` was verified through a trust ceremony.
    pub fn trust_user(&mut self, user: UserId) {
        self.trusted.insert(user);
    }

    /// Whether `user` is trusted as an object creator.
    pub fn is_trusted(&self, user: &UserId) -> bool {
        self.trusted.contains(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn device_authorization_verifies_and_detects_tampering() {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let user = UserIdentity::generate(&mut rng);
        let device = DeviceIdentity::generate(&user, 5, &mut rng);
        let record = device.record();
        assert_eq!(record.authorization.verify(), Ok(()));
        assert_eq!(record.authorization.body.user, user.id());
        assert_eq!(record.authorization.body.device, device.id());

        let mut forged = record.authorization.clone();
        forged.body.issued_at = 6;
        assert_eq!(forged.verify(), Err(IdentityError::BadSignature));

        let other = UserIdentity::generate(&mut rng);
        let mut reassigned = record.authorization.clone();
        reassigned.body.user = other.id();
        assert_eq!(reassigned.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn identity_generation_is_deterministic_from_seed() {
        let a = UserIdentity::generate(&mut ChaCha20Rng::from_seed([9; 32]));
        let b = UserIdentity::generate(&mut ChaCha20Rng::from_seed([9; 32]));
        assert_eq!(a.id(), b.id());
    }

    #[test]
    fn debug_output_never_prints_private_material() {
        let mut rng = ChaCha20Rng::from_seed([2; 32]);
        let user = UserIdentity::generate(&mut rng);
        let device = DeviceIdentity::generate(&user, 0, &mut rng);
        let rendered = format!("{user:?} {device:?}");
        assert!(rendered.len() < 80, "{rendered}");
    }
}
