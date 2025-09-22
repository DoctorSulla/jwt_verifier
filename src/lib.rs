use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
#[cfg(not(test))]
use reqwest::Client;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

mod stubs;

#[derive(Error, Debug)]
pub enum JwtParsingError {
    #[error("AUD does not match provided client id")]
    ClientIdMismatch,
    #[error("The token start date is in the future")]
    TokenFromFuture,
    #[error("The token is expired")]
    TokenExpired,
    #[error("Kid not found")]
    KidNotPresentInList,
    #[error("Signature does not match metadata and claims")]
    SignatureDoesNotMatch,
    #[error("JWT must have three separate parts")]
    InvalidNumberOfParts,
    #[error("Error from base 64 decoder: {0}")]
    DecodingError(#[from] DecodeError),
    #[error("Error from serde_json: {0}")]
    DeserializeError(#[from] serde_json::Error),
    #[error("Error from reqwest: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Error from rsa: {0}")]
    RsaError(#[from] rsa::Error),
    #[error("Error from rsa signature: {0}")]
    RsaSignatureError(#[from] rsa::signature::Error),
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
    email: String,
    email_verified: bool,
    nbf: i64,
    name: String,
    picture: Option<String>,
    given_name: String,
    family_name: String,
    iat: i64,
    exp: i64,
    jti: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GoogleKeys {
    keys: Vec<Key>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Key {
    kid: String,
    alg: String,
    kty: String,
    e: String,
    n: String,
    r#use: String,
}

#[cfg(not(test))]
const GOOGLE_KEY_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

#[cfg(test)]
pub async fn get_google_keys() -> Result<GoogleKeys, JwtParsingError> {
    let response: GoogleKeys = serde_json::from_str(stubs::KEYS_STUB)?;
    Ok(response)
}

#[cfg(not(test))]
pub async fn get_google_keys() -> Result<GoogleKeys, JwtParsingError> {
    let client = Client::new();
    let response: GoogleKeys = client.get(GOOGLE_KEY_URL).send().await?.json().await?;

    Ok(response)
}

pub async fn fetch_key_by_kid(kid: &str) -> Result<RsaPublicKey, JwtParsingError> {
    let response = get_google_keys().await?;

    let key = match response.keys.into_iter().find(|v| v.kid == kid) {
        Some(v) => v,
        None => return Err(JwtParsingError::KidNotPresentInList),
    };

    let decoded_n = URL_SAFE_NO_PAD.decode(key.n)?;

    let n = BigUint::from_bytes_be(&decoded_n);

    let decoded_e = URL_SAFE_NO_PAD.decode(key.e.as_bytes())?;

    let e = BigUint::from_bytes_be(&decoded_e);

    Ok(RsaPublicKey::new(n, e)?)
}

pub async fn verify(
    raw_jwt: &str,
    validate_expiry: bool,
    client_id: &str,
) -> Result<Claims, JwtParsingError> {
    let parts: Vec<&str> = raw_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtParsingError::InvalidNumberOfParts);
    }

    let raw_metadata = parts[0];
    let raw_claims = parts[1];
    let raw_signature = parts[2];

    let decoded_metadata = URL_SAFE_NO_PAD.decode(raw_metadata.as_bytes())?;
    let decoded_claims = URL_SAFE_NO_PAD.decode(raw_claims.as_bytes())?;

    let metadata: Metadata = serde_json::from_slice(&decoded_metadata)?;
    let claims: Claims = serde_json::from_slice(&decoded_claims)?;

    if validate_expiry {
        check_timestamps(&claims)?
    }

    if &claims.aud != client_id {
        return Err(JwtParsingError::ClientIdMismatch);
    }

    let decoded_signature = URL_SAFE_NO_PAD.decode(raw_signature.as_bytes())?;

    let signature = Signature::try_from(&decoded_signature[..])?;

    let to_sign = format!("{}.{}", raw_metadata, raw_claims);

    let public_key = fetch_key_by_kid(&metadata.kid).await?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    let _ = match verifying_key.verify(&to_sign.as_bytes(), &signature) {
        Ok(_v) => return Ok(claims),
        Err(_e) => return Err(JwtParsingError::SignatureDoesNotMatch),
    };
}

pub fn check_timestamps(claims: &Claims) -> Result<(), JwtParsingError> {
    let now = Utc::now().timestamp();
    //let now = 1758440560;
    if now > claims.exp {
        return Err(JwtParsingError::TokenExpired);
    } else if now < claims.nbf {
        return Err(JwtParsingError::TokenFromFuture);
    } else if now < claims.iat {
        return Err(JwtParsingError::TokenFromFuture);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_JWT: &str = r##"eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3ZjA3OGYyNjQ3ZThjZDAxOWM0MGRhOTU2OWU0ZjUyNDc5OTEwOTQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5ODgzNDM5Mzg1MTktdmxlN2twczJsNWY2Y2Ruamx1aWJkYTI1bzY2aDJqcG4uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5ODgzNDM5Mzg1MTktdmxlN2twczJsNWY2Y2Ruamx1aWJkYTI1bzY2aDJqcG4uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDMwOTU0MzkwNjM4NjcyOTg2NzEiLCJlbWFpbCI6Im1hdHRoZXcuaGFsbGlkYXlAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5iZiI6MTc1ODQ0MDY1NiwibmFtZSI6Ik1hdHRoZXcgSGFsbGlkYXkiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSkJ5ZTlNenpZaUxINUQ0azktLVVwNUlZbzN0YVFsYm53RVNISmdIel9oYkFTOEhWeXg9czk2LWMiLCJnaXZlbl9uYW1lIjoiTWF0dGhldyIsImZhbWlseV9uYW1lIjoiSGFsbGlkYXkiLCJpYXQiOjE3NTg0NDA5NTYsImV4cCI6MTc1ODQ0NDU1NiwianRpIjoiY2E3ZWZmZjQxMzNmYzU0NGVmY2JhNzYxZjY4Mzk2MThmZWU5ZThjZiJ9.o5CVIXUiIZYW2-CBwiT9CjbaExnjiH90_QfX1r4hmKePachwLE_KG54p6octPwWx_L3COM4thQun7vx6k1ShFSx7x3pIit2BgwE6iJsZy9fSHdEGhjKnFuNZnocDyDCY94xYyaiLZCp5G39rPC8VmY8flBnnt5YjlmoX0pY_C_SzJhSZLe1oMSj1P4ZfyJkyg-sXtRMw32Z7whRCGN70_u9SkJXdZCoTNUWbkIQwzRrehW63Omw_9iRyRcZ9AbAlTxSi1YrkGJsrPclCK2HZmtXqybmlBgu2Zh6tejfDXGZntRrFMmx7QpJyuWRdPRmyPZSPXn8UOc3GrMuRUOF54g"##;

    #[tokio::test]
    async fn valid_jwt_signature_matches() {
        let verify = verify(
            VALID_JWT,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
        println!("{:?}", verify);
        assert!(verify.is_ok());
    }
}
