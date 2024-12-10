use jsonwebtoken::{jwk::KeyAlgorithm, Algorithm};

use crate::JwkError;



pub fn try_get_supported_algorithm (check: KeyAlgorithm) -> Result<Algorithm, JwkError> {
    let supported = match check {
        KeyAlgorithm::HS256 => Algorithm::HS256,
        KeyAlgorithm::HS384 => Algorithm::HS384,
        KeyAlgorithm::HS512 => Algorithm::HS512,
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::ES384 => Algorithm::ES384,
        KeyAlgorithm::RS256 => Algorithm::RS256,
        KeyAlgorithm::RS384 => Algorithm::RS384,
        KeyAlgorithm::RS512 => Algorithm::RS512,
        KeyAlgorithm::PS256 => Algorithm::PS256,
        KeyAlgorithm::PS384 => Algorithm::PS384,
        KeyAlgorithm::PS512 => Algorithm::PS512,
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        KeyAlgorithm::RSA1_5 => return Err(JwkError::UnsupportedAlgorithm { algorithm: KeyAlgorithm::RSA1_5 }),
        KeyAlgorithm::RSA_OAEP => return Err(JwkError::UnsupportedAlgorithm { algorithm: KeyAlgorithm::RSA_OAEP }),
        KeyAlgorithm::RSA_OAEP_256 => return Err(JwkError::UnsupportedAlgorithm { algorithm: KeyAlgorithm::RSA_OAEP_256 }),
    };

    Ok(supported)
}
