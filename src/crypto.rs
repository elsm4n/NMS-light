use std::sync::Arc;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use thiserror::Error;

const ENVELOPE_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct SecretCipher {
    key: Arc<[u8; 32]>,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("secure random generation failed")]
    Random,
    #[error("unsupported ciphertext envelope")]
    InvalidEnvelope,
    #[error("authenticated encryption failed")]
    Authentication,
    #[error("decrypted value is not valid UTF-8")]
    InvalidUtf8,
}

impl SecretCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Arc::new(key) }
    }

    pub fn encrypt(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::Random)?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        let nonce =
            Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::InvalidEnvelope)?;
        let encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::Authentication)?;

        let mut envelope = Vec::with_capacity(1 + NONCE_LEN + encrypted.len());
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&encrypted);
        Ok(envelope)
    }

    pub fn decrypt(&self, associated_data: &[u8], envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if envelope.len() < 1 + NONCE_LEN + TAG_LEN || envelope.first() != Some(&ENVELOPE_VERSION) {
            return Err(CryptoError::InvalidEnvelope);
        }

        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        let nonce = Nonce::try_from(&envelope[1..1 + NONCE_LEN])
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope[1 + NONCE_LEN..],
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::Authentication)
    }

    pub fn decrypt_string(
        &self,
        associated_data: &[u8],
        envelope: &[u8],
    ) -> Result<String, CryptoError> {
        let plaintext = self.decrypt(associated_data, envelope)?;
        String::from_utf8(plaintext).map_err(|_| CryptoError::InvalidUtf8)
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoError, SecretCipher};

    #[test]
    fn authenticated_encryption_round_trips() -> Result<(), CryptoError> {
        let cipher = SecretCipher::new([7_u8; 32]);
        let encrypted = cipher.encrypt(b"device:42:community", b"sensitive-value")?;
        let decrypted = cipher.decrypt_string(b"device:42:community", &encrypted)?;
        assert_eq!(decrypted, "sensitive-value");
        assert_ne!(encrypted, b"sensitive-value");
        Ok(())
    }

    #[test]
    fn ciphertext_is_bound_to_its_associated_data() -> Result<(), CryptoError> {
        let cipher = SecretCipher::new([9_u8; 32]);
        let encrypted = cipher.encrypt(b"device:42:community", b"sensitive-value")?;
        assert!(matches!(
            cipher.decrypt(b"device:43:community", &encrypted),
            Err(CryptoError::Authentication)
        ));
        Ok(())
    }
}
