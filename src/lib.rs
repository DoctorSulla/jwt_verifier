use crate::error::JwtValidationError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use reqwest::Client;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[cfg(test)]
use rsa::RsaPrivateKey;
#[cfg(test)]
use rsa::pkcs1v15::SigningKey;
#[cfg(test)]
use rsa::rand_core::impls::fill_bytes_via_next;
#[cfg(test)]
use rsa::traits::PublicKeyParts;
#[cfg(test)]
use signature::{SignatureEncoding, SignerMut};
#[cfg(test)]
use std::sync::{Arc, LazyLock};

pub mod error;

pub struct JwtVerifierClient {
    client: Client,
    cached_keys: GoogleKeys,
    cache_expiry: i64,
}

#[derive(Serialize, Deserialize, Debug)]
struct Metadata {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Claims {
    iss: String,
    azp: Option<String>,
    aud: String,
    sub: String,
    hd: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    nbf: Option<i64>,
    name: Option<String>,
    picture: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    iat: Option<i64>,
    exp: i64,
    jti: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct GoogleKeys {
    keys: Vec<Key>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Key {
    kid: String,
    alg: String,
    kty: String,
    e: String,
    n: String,
    r#use: String,
}

#[cfg(test)]
pub static TEST_KEYPAIR: LazyLock<Arc<(RsaPrivateKey, RsaPublicKey)>> = LazyLock::new(|| {
    let mut rng = rand::thread_rng();
    let privk = RsaPrivateKey::new_with_exp(&mut rng, 2048, &BigUint::from(65537u32))
        .expect("Failed to generate test keypair");
    let pubk = RsaPublicKey::from(&privk);
    Arc::new((privk, pubk))
});

const GOOGLE_KEY_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const DEFAULT_EXPIRY: i64 = 300;
const MARGIN: i64 = 30;

async fn get_google_keys(client: Client) -> Result<(GoogleKeys, i64), JwtValidationError> {
    // Send request and capture headers before consuming the body
    let response = client.get(GOOGLE_KEY_URL).send().await?;
    let headers = response.headers().clone();

    let now = Utc::now().timestamp();
    let mut expiry: i64 = now + DEFAULT_EXPIRY;

    // Prefer Cache-Control:max-age if present
    if let Some(v) = headers.get("cache-control") {
        if let Ok(s) = v.to_str() {
            // Find "max-age=" and parse the following digits
            if let Some(pos) = s.find("max-age=") {
                let rest = &s[pos + "max-age=".len()..];
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if !digits.is_empty()
                    && let Ok(seconds) = digits.parse::<i64>()
                {
                    expiry = now + seconds;
                }
            }
        }
    } else if let Some(v) = headers.get("expires") {
        // Fallback to Expires header if Cache-Control is not present
        if let Ok(s) = v.to_str() {
            // Try common HTTP date formats. Ignore parse errors and keep default.
            if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(s) {
                expiry = dt.timestamp();
            } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                expiry = dt.timestamp();
            }
        }
    }

    let keys: GoogleKeys = response.json().await?;

    Ok((keys, expiry))
}

impl JwtVerifierClient {
    /**
     * Create a new JwtVerifierClient instance for testing purposes.
     * This method is only available in test environments and uses stubbed keys and a cache with a 10 year expiry.
     */
    #[cfg(test)]
    async fn test_client(keys: GoogleKeys) -> Result<Self, JwtValidationError> {
        let client = Client::new();
        let cached_keys = keys;
        let cache_expiry = Utc::now().timestamp() + 3600 * 24 * 3650;

        Ok(Self {
            client,
            cached_keys,
            cache_expiry,
        })
    }

    pub async fn new() -> Result<Self, JwtValidationError> {
        let client = Client::new();
        let (cached_keys, cache_expiry) = get_google_keys(client.clone()).await?;

        Ok(Self {
            client,
            cached_keys,
            cache_expiry,
        })
    }

    fn cache_expired(&self) -> bool {
        Utc::now().timestamp() > self.cache_expiry
    }

    async fn refresh_keys(&mut self) -> Result<(), JwtValidationError> {
        let (cached_keys, cache_expiry) = get_google_keys(self.client.clone()).await?;
        self.cached_keys = cached_keys;
        self.cache_expiry = cache_expiry;
        Ok(())
    }

    pub async fn fetch_key_by_kid(
        &mut self,
        kid: &str,
    ) -> Result<RsaPublicKey, JwtValidationError> {
        if self.cache_expired() {
            self.refresh_keys().await?;
        }

        let key = match self.cached_keys.keys.iter().find(|v| v.kid == kid) {
            Some(v) => v,
            None => return Err(JwtValidationError::KidNotPresentInList),
        };

        let decoded_n = URL_SAFE_NO_PAD.decode(&key.n)?;

        let n = BigUint::from_bytes_be(&decoded_n);

        let decoded_e = URL_SAFE_NO_PAD.decode(key.e.as_bytes())?;

        let e = BigUint::from_bytes_be(&decoded_e);

        Ok(RsaPublicKey::new(n, e)?)
    }

    pub async fn verify(
        &mut self,
        raw_jwt: &str,
        validate_expiry: bool,
        client_id: &str,
    ) -> Result<Claims, JwtValidationError> {
        let parts: Vec<&str> = raw_jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtValidationError::InvalidNumberOfParts);
        }

        let raw_metadata = parts[0];
        let raw_claims = parts[1];
        let raw_signature = parts[2];

        let decoded_metadata = URL_SAFE_NO_PAD.decode(raw_metadata.as_bytes())?;
        let decoded_claims = URL_SAFE_NO_PAD.decode(raw_claims.as_bytes())?;

        let metadata: Metadata = serde_json::from_slice(&decoded_metadata)?;

        if metadata.alg.to_uppercase() != "RS256" {
            return Err(JwtValidationError::UnsupportedAlgorithm);
        }

        let claims: Claims = serde_json::from_slice(&decoded_claims)?;

        if claims.iss != "accounts.google.com" && claims.iss != "https://accounts.google.com" {
            return Err(JwtValidationError::IssuerMismatch);
        }

        if validate_expiry {
            check_timestamps(&claims)?;
        }

        if claims.aud != client_id {
            return Err(JwtValidationError::ClientIdMismatch);
        }

        let decoded_signature = URL_SAFE_NO_PAD.decode(raw_signature.as_bytes())?;

        let signature = Signature::try_from(&decoded_signature[..])?;

        let to_sign = format!("{}.{}", raw_metadata, raw_claims);

        let public_key = self.fetch_key_by_kid(&metadata.kid).await?;

        let verifying_key = VerifyingKey::<Sha256>::new(public_key);

        let _ = match verifying_key.verify(to_sign.as_bytes(), &signature) {
            Ok(_v) => return Ok(claims),
            Err(_e) => return Err(JwtValidationError::SignatureDoesNotMatch),
        };
    }
}

pub fn check_timestamps(claims: &Claims) -> Result<(), JwtValidationError> {
    let now = Utc::now().timestamp();
    if now > claims.exp + MARGIN {
        return Err(JwtValidationError::TokenExpired);
    }
    if let Some(nbf) = claims.nbf
        && now + MARGIN < nbf
    {
        return Err(JwtValidationError::TokenFromFuture);
    }
    if let Some(iat) = claims.iat
        && now + MARGIN < iat
    {
        return Err(JwtValidationError::TokenFromFuture);
    }
    Ok(())
}

#[cfg(test)]
fn generate_mock_keys() -> (GoogleKeys, RsaPrivateKey) {
    let mut rng = rand::thread_rng();

    let keypair = Arc::clone(&TEST_KEYPAIR);
    let priv_key = keypair.0.clone();
    let pub_key = keypair.1.clone();

    let mut bytes = [0u8; 16];
    fill_bytes_via_next(&mut rng, &mut bytes);
    let kid = URL_SAFE_NO_PAD.encode(bytes);

    let key = Key {
        e: "AQAB".to_string(),
        n: URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be()),
        kid,
        alg: "RS256".to_string(),
        kty: "RSA".to_string(),
        r#use: "sig".to_string(),
    };

    let keys = GoogleKeys { keys: vec![key] };

    (keys, priv_key)
}

#[cfg(test)]
fn generate_test_jwt(nbf: i64, iat: i64, exp: i64) -> (GoogleKeys, String) {
    let (keys, private_key) = generate_mock_keys();
    let meta = Metadata {
        alg: "RS256".to_string(),
        kid: keys.keys[0].kid.clone(),
        typ: "JWT".to_string(),
    };

    let claims =  Claims {
    iss: "https://accounts.google.com".to_string(),
    azp: Some("988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com".to_string()),
    aud: "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com".to_string(),
    sub: "103095439063867298671".to_string(),
    hd: None,
    email: Some("matthew.halliday@gmail.com".to_string()),
    email_verified: Some(true),
    nbf: Some(nbf),
    name: Some("Matthew Halliday".to_string()),
    picture: Some("https://lh3.googleusercontent.com/a/ACg8ocJBye9MzzYiLH5D4k9--Up5IYo3taQlbnwESHJgHz_hbAS8HVyx=s96-c".to_string()),
    given_name: Some("Matthew".to_string()),
    family_name: Some("Halliday".to_string()),
    iat: Some(iat),
    exp: exp,
    jti: Some("ca7efff4133fc544efcba761f6839618fee9e8cf".to_string()) };

    let meta_encoded = URL_SAFE_NO_PAD.encode(serde_json::to_string(&meta).unwrap());
    let claims_encoded = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());

    let to_sign = format!("{meta_encoded}.{claims_encoded}");
    let mut signing_key = SigningKey::<Sha256>::new(private_key);

    let signature = signing_key.sign(to_sign.as_bytes()).to_bytes();
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);
    let jwt = format!("{meta_encoded}.{claims_encoded}.{encoded_signature}");
    (keys, jwt)
}

#[cfg(test)]
mod tests;
