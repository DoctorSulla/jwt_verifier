use std::collections::HashMap;

use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Client;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtParsingError {
    #[error("Signature does not match metadata and payload")]
    SignatureDoesNotMatch,
    #[error("JWT must have three separate parts")]
    InvalidNumberOfParts,
    #[error("Error from base 64 decoder: {0}")]
    DecodingError(#[from] DecodeError),
    #[error("Error from serde_json: {0}")]
    DeserializeError(#[from] serde_json::Error),
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
    azp: String,
    aud: String,
    sub: String,
    email: String,
    email_verified: bool,
    nbf: i64,
    name: String,
    picture: String,
    given_name: String,
    family_name: String,
    iat: i64,
    exp: i64,
    jti: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct GoogleKeys {
    keys: Vec<Key>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Key {
    kid: String,
    alg: String,
    kty: String,
    e: String,
    n: String,
    r#use: String,
}

const GOOGLE_KEY_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

pub async fn fetch_key_by_kid(kid: &str) -> Result<RsaPublicKey, JwtParsingError> {
    let client = Client::new();
    let response: GoogleKeys = client
        .get(GOOGLE_KEY_URL)
        .send()
        .await
        .expect("Unable to fetch keys from Google")
        .json()
        .await
        .expect("Unable to parse keys response into expected format");

    let key = response
        .keys
        .into_iter()
        .find(|v| v.kid == kid)
        .expect("Provided kid not found in response");

    let decoded_n = URL_SAFE_NO_PAD.decode(key.n)?;

    let n = BigUint::from_bytes_be(&decoded_n);

    let decoded_e = URL_SAFE_NO_PAD.decode(key.e.as_bytes())?;

    // Get the decimal value of e
    let mut total: u32 = 0;
    for (index, byte) in decoded_e.iter().enumerate() {
        total += u32::pow(256, index as u32) * *byte as u32;
    }

    let e = BigUint::from(total);

    Ok(RsaPublicKey::new(n, e).unwrap())
}

pub async fn verify(raw_jwt: &str) -> Result<Claims, JwtParsingError> {
    let parts: Vec<&str> = raw_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtParsingError::InvalidNumberOfParts);
    }

    let raw_metadata = parts[0];
    let raw_payload = parts[1];
    let raw_signature = parts[2];

    let decoded_metadata = URL_SAFE_NO_PAD.decode(raw_metadata.as_bytes())?;
    let decoded_payload = URL_SAFE_NO_PAD.decode(raw_payload.as_bytes())?;

    let metadata: Metadata = serde_json::from_slice(&decoded_metadata)?;
    let payload: Claims = serde_json::from_slice(&decoded_payload)?;

    let decoded_signature = URL_SAFE_NO_PAD.decode(raw_signature.as_bytes()).unwrap();

    let signature = Signature::try_from(&decoded_signature[..]).unwrap();

    let to_sign = format!("{}.{}", raw_metadata, raw_payload);

    let public_key = fetch_key_by_kid(&metadata.kid).await.unwrap();

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    let _ = match verifying_key.verify(&to_sign.as_bytes(), &signature) {
        Ok(_v) => return Ok(payload),
        Err(_e) => return Err(JwtParsingError::SignatureDoesNotMatch),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_JWT: &str = r##"eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3ZjA3OGYyNjQ3ZThjZDAxOWM0MGRhOTU2OWU0ZjUyNDc5OTEwOTQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5ODgzNDM5Mzg1MTktdmxlN2twczJsNWY2Y2Ruamx1aWJkYTI1bzY2aDJqcG4uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5ODgzNDM5Mzg1MTktdmxlN2twczJsNWY2Y2Ruamx1aWJkYTI1bzY2aDJqcG4uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDMwOTU0MzkwNjM4NjcyOTg2NzEiLCJlbWFpbCI6Im1hdHRoZXcuaGFsbGlkYXlAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5iZiI6MTc1ODQ0MDY1NiwibmFtZSI6Ik1hdHRoZXcgSGFsbGlkYXkiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSkJ5ZTlNenpZaUxINUQ0azktLVVwNUlZbzN0YVFsYm53RVNISmdIel9oYkFTOEhWeXg9czk2LWMiLCJnaXZlbl9uYW1lIjoiTWF0dGhldyIsImZhbWlseV9uYW1lIjoiSGFsbGlkYXkiLCJpYXQiOjE3NTg0NDA5NTYsImV4cCI6MTc1ODQ0NDU1NiwianRpIjoiY2E3ZWZmZjQxMzNmYzU0NGVmY2JhNzYxZjY4Mzk2MThmZWU5ZThjZiJ9.o5CVIXUiIZYW2-CBwiT9CjbaExnjiH90_QfX1r4hmKePachwLE_KG54p6octPwWx_L3COM4thQun7vx6k1ShFSx7x3pIit2BgwE6iJsZy9fSHdEGhjKnFuNZnocDyDCY94xYyaiLZCp5G39rPC8VmY8flBnnt5YjlmoX0pY_C_SzJhSZLe1oMSj1P4ZfyJkyg-sXtRMw32Z7whRCGN70_u9SkJXdZCoTNUWbkIQwzRrehW63Omw_9iRyRcZ9AbAlTxSi1YrkGJsrPclCK2HZmtXqybmlBgu2Zh6tejfDXGZntRrFMmx7QpJyuWRdPRmyPZSPXn8UOc3GrMuRUOF54g"##;

    #[tokio::test]
    async fn valid_jwt_signature_matches() {
        let verify = verify(VALID_JWT).await;
        assert!(verify.is_ok());
    }
}
