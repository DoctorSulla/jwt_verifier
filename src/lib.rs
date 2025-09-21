use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtParsingError {
    #[error("JWT must have three separate parts")]
    InvalidNumberOfParts,
    #[error("Error from base 64 decoder: {0}")]
    InvalidMetaData(#[from] DecodeError),
}

#[derive(Serialize, Deserialize, Debug)]
struct Metadata {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct GoogleJwt {
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

// {"iss":"https://accounts.google.com","azp":"988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com","aud":"988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com","sub":"103095439063867298671","email":"matthew.halliday@gmail.com","email_verified":true,"nbf":1758440656,"name":"Matthew Halliday","picture":"https://lh3.googleusercontent.com/a/ACg8ocJBye9MzzYiLH5D4k9--Up5IYo3taQlbnwESHJgHz_hbAS8HVyx=s96-c","given_name":"Matthew","family_name":"Halliday","iat":1758440956,"exp":1758444556,"jti":"ca7efff4133fc544efcba761f6839618fee9e8cf"}
//Metadata { alg: "RS256", kid: "07f078f2647e8cd019c40da9569e4f5247991094", typ: "JWT" }

pub fn verify(raw_jwt: &str) -> Result<String, JwtParsingError> {
    let raw_n = "pX0uFURVHarx3LZWaF4LnP3Kh2MbVl3iEOpQUcSxADEutXj383X9ZU6wdCmX4y_K23b0BU6oID1q0jkEE3sfQYaJJ7Qj9u2UnT-G9oGUoAn9GV1AYWxCNSz9mCrIJxP7ywcrvWJsKiYo7Q3Q-Tz44W1dCdVDQW870eixQSCnc6xrz4tu7RKrpeStH_GDhNIY3tXOuZvlPIvv4PH5sL39RaQ36T8ceGTWVDlYogKtvUUWl2YCGhz0f5y_ToRKU_WjnOmrN25_x30chCH3uz6I1RUa8vTAjbxCk4H5d1NmFNgV1zMSUKG0qo2d91fbyjmIRyODPVuUzSozREcVeSF_3Q";

    let decoded_n = URL_SAFE_NO_PAD.decode(raw_n).unwrap();

    let n = BigUint::from_bytes_be(&decoded_n);

    let raw_e = "AQAB";

    let decoded_e = URL_SAFE_NO_PAD.decode(raw_e.as_bytes()).unwrap();

    let mut u32_bytes: Vec<u32> = decoded_e.iter().map(|v| *v as u32).collect();

    let e = BigUint::new(u32_bytes);

    let parts: Vec<&str> = raw_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtParsingError::InvalidNumberOfParts);
    }

    let raw_metadata = parts[0];
    let raw_payload = parts[1];
    let raw_signature = parts[2];

    let to_sign = format!("{}.{}", raw_metadata, raw_payload);

    let hash = Sha256::digest(to_sign);
    println!("{:X?}", hash);

    //println!("{:?}", hex);

    let public_key = RsaPublicKey::new(n, e).unwrap();

    //public_key.verify(to_sign, hashed, sig)

    let decoded_metadata = URL_SAFE_NO_PAD.decode(raw_metadata.as_bytes()).unwrap();
    let decoded_payload = URL_SAFE_NO_PAD.decode(raw_payload.as_bytes()).unwrap();

    let metadata: Metadata = serde_json::from_slice(&decoded_metadata).unwrap();
    let payload: GoogleJwt = serde_json::from_slice(&decoded_payload).unwrap();
    println!("{metadata:?}");
    println!("{payload:?}");

    Ok("Success".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_JWT: &str = r##"eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3ZjA3OGYyNjQ3ZThjZDAxOWM0MGRhOTU2OWU0ZjUyNDc5OTEwOTQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5ODgzNDM5Mzg1MTktdmxlN2twczJsNWY2Y2Ruamx1aWJkYTI1bzY2aDJqcG4uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5ODgzNDM5Mzg1MTktdmxlN2twczJsNWY2Y2Ruamx1aWJkYTI1bzY2aDJqcG4uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDMwOTU0MzkwNjM4NjcyOTg2NzEiLCJlbWFpbCI6Im1hdHRoZXcuaGFsbGlkYXlAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5iZiI6MTc1ODQ0MDY1NiwibmFtZSI6Ik1hdHRoZXcgSGFsbGlkYXkiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSkJ5ZTlNenpZaUxINUQ0azktLVVwNUlZbzN0YVFsYm53RVNISmdIel9oYkFTOEhWeXg9czk2LWMiLCJnaXZlbl9uYW1lIjoiTWF0dGhldyIsImZhbWlseV9uYW1lIjoiSGFsbGlkYXkiLCJpYXQiOjE3NTg0NDA5NTYsImV4cCI6MTc1ODQ0NDU1NiwianRpIjoiY2E3ZWZmZjQxMzNmYzU0NGVmY2JhNzYxZjY4Mzk2MThmZWU5ZThjZiJ9.o5CVIXUiIZYW2-CBwiT9CjbaExnjiH90_QfX1r4hmKePachwLE_KG54p6octPwWx_L3COM4thQun7vx6k1ShFSx7x3pIit2BgwE6iJsZy9fSHdEGhjKnFuNZnocDyDCY94xYyaiLZCp5G39rPC8VmY8flBnnt5YjlmoX0pY_C_SzJhSZLe1oMSj1P4ZfyJkyg-sXtRMw32Z7whRCGN70_u9SkJXdZCoTNUWbkIQwzRrehW63Omw_9iRyRcZ9AbAlTxSi1YrkGJsrPclCK2HZmtXqybmlBgu2Zh6tejfDXGZntRrFMmx7QpJyuWRdPRmyPZSPXn8UOc3GrMuRUOF54g"##;

    #[test]
    fn it_works() {
        match verify(VALID_JWT) {
            Ok(_v) => panic!(""),
            Err(e) => println!("{:?}", e),
        };
        assert_eq!(4, 4);
    }
}
