use crate::tests::JwtValidationError;
use crate::*;

const _VALID_JWT: &str = r##"eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3ZjA3OGYyNjQ3ZThjZDAxOWM0MGRhOTU2OWU0ZjUyNDc5OTEwOTQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5ODgzNDM5Mzg1MTktdmxlN2twczJsNWY2Y2Ruamx1aWJkYTI1bzY2aDJqcG4uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5ODgzNDM5Mzg1MTktdmxlN2twczJsNWY2Y2Ruamx1aWJkYTI1bzY2aDJqcG4uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDMwOTU0MzkwNjM4NjcyOTg2NzEiLCJlbWFpbCI6Im1hdHRoZXcuaGFsbGlkYXlAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5iZiI6MTc1ODQ0MDY1NiwibmFtZSI6Ik1hdHRoZXcgSGFsbGlkYXkiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSkJ5ZTlNenpZaUxINUQ0azktLVVwNUlZbzN0YVFsYm53RVNISmdIel9oYkFTOEhWeXg9czk2LWMiLCJnaXZlbl9uYW1lIjoiTWF0dGhldyIsImZhbWlseV9uYW1lIjoiSGFsbGlkYXkiLCJpYXQiOjE3NTg0NDA5NTYsImV4cCI6MTc1ODQ0NDU1NiwianRpIjoiY2E3ZWZmZjQxMzNmYzU0NGVmY2JhNzYxZjY4Mzk2MThmZWU5ZThjZiJ9.o5CVIXUiIZYW2-CBwiT9CjbaExnjiH90_QfX1r4hmKePachwLE_KG54p6octPwWx_L3COM4thQun7vx6k1ShFSx7x3pIit2BgwE6iJsZy9fSHdEGhjKnFuNZnocDyDCY94xYyaiLZCp5G39rPC8VmY8flBnnt5YjlmoX0pY_C_SzJhSZLe1oMSj1P4ZfyJkyg-sXtRMw32Z7whRCGN70_u9SkJXdZCoTNUWbkIQwzRrehW63Omw_9iRyRcZ9AbAlTxSi1YrkGJsrPclCK2HZmtXqybmlBgu2Zh6tejfDXGZntRrFMmx7QpJyuWRdPRmyPZSPXn8UOc3GrMuRUOF54g"##;

#[tokio::test]
async fn valid_jwt_signature_matches() {
    let (keys, jwt) = generate_test_jwt(
        Utc::now().timestamp() - 30,
        Utc::now().timestamp(),
        Utc::now().timestamp() + 3600,
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn invalid_client_id_fails() {
    let (keys, jwt) = generate_test_jwt(
        Utc::now().timestamp() - 30,
        Utc::now().timestamp(),
        Utc::now().timestamp() + 3600,
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o76h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(matches!(result, Err(JwtValidationError::ClientIdMismatch)));
}

#[tokio::test]
async fn expired_jwt_fails() {
    let (keys, jwt) = generate_test_jwt(
        Utc::now().timestamp() - 7230,
        Utc::now().timestamp() - 7200,
        Utc::now().timestamp() - 3600,
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(matches!(result, Err(JwtValidationError::TokenExpired)));
}

#[tokio::test]
async fn invalid_signature_fails() {
    let (keys, jwt) = generate_test_jwt(
        Utc::now().timestamp() - 30,
        Utc::now().timestamp(),
        Utc::now().timestamp() + 3600,
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();

    let (_keys, another_jwt) = generate_test_jwt(
        Utc::now().timestamp() - 30,
        Utc::now().timestamp(),
        Utc::now().timestamp() + 3600,
    );

    let split_jwt: Vec<&str> = jwt.split('.').collect();
    let split_another_jwt: Vec<&str> = another_jwt.split('.').collect();

    let jwt_with_invalid_signature =
        format!("{}.{}.{}", split_jwt[0], split_jwt[1], split_another_jwt[2]);

    let result = jwt_client
        .verify(
            &jwt_with_invalid_signature,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;

    println!("{:?}", result);
    assert!(matches!(
        result,
        Err(JwtValidationError::SignatureDoesNotMatch)
    ));
}

#[tokio::test]
async fn token_expires_within_margin_should_pass() {
    let now = Utc::now().timestamp();
    let (keys, jwt) = generate_test_jwt(
        now - MARGIN,
        now,
        now + (MARGIN - 15), // expires in 15 seconds (within MARGIN of 30)
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(
        result.is_ok(),
        "Token should be valid when expiring within MARGIN"
    );
}

#[tokio::test]
async fn token_expires_just_beyond_margin_should_fail() {
    let now = Utc::now().timestamp();
    let (keys, jwt) = generate_test_jwt(
        now - MARGIN,
        now,
        now - (MARGIN + 1), // expires 1 second beyond MARGIN (now - (MARGIN + 1) + 30 = now - 1)
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(
        matches!(result, Err(JwtValidationError::TokenExpired)),
        "Token should be invalid when expiring beyond MARGIN"
    );
}

#[tokio::test]
async fn token_nbf_within_margin_should_pass() {
    let now = Utc::now().timestamp();
    let (keys, jwt) = generate_test_jwt(
        now + (MARGIN - 15), // nbf in 15 seconds (within MARGIN of 30)
        now,
        now + 3600,
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(
        result.is_ok(),
        "Token should be valid when nbf is within MARGIN"
    );
}

#[tokio::test]
async fn token_nbf_exactly_at_margin_should_pass() {
    let now = Utc::now().timestamp();
    let (keys, jwt) = generate_test_jwt(
        now + MARGIN, // nbf exactly at MARGIN boundary (now + MARGIN - 30 = now)
        now,
        now + 3600,
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(
        result.is_ok(),
        "Token should be valid when nbf is exactly at MARGIN boundary"
    );
}

#[tokio::test]
async fn token_nbf_beyond_margin_should_fail() {
    let now = Utc::now().timestamp();
    let (keys, jwt) = generate_test_jwt(
        now + (MARGIN + 31), // nbf 61 seconds in future, so now + MARGIN < nbf (61)
        now,
        now + 3600,
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(
        matches!(result, Err(JwtValidationError::TokenFromFuture)),
        "Token should be invalid when nbf is beyond MARGIN"
    );
}

#[tokio::test]
async fn token_iat_within_margin_should_pass() {
    let now = Utc::now().timestamp();
    let (keys, jwt) = generate_test_jwt(
        now - MARGIN,
        now + (MARGIN - 15), // iat in 15 seconds (within MARGIN of 30)
        now + 3600,
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(
        result.is_ok(),
        "Token should be valid when iat is within MARGIN"
    );
}

#[tokio::test]
async fn token_iat_exactly_at_margin_should_pass() {
    let now = Utc::now().timestamp();
    let (keys, jwt) = generate_test_jwt(
        now - MARGIN,
        now + MARGIN, // iat exactly at MARGIN boundary (now + MARGIN - 30 = now)
        now + 3600,
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(
        result.is_ok(),
        "Token should be valid when iat is exactly at MARGIN boundary"
    );
}

#[tokio::test]
async fn token_iat_beyond_margin_should_fail() {
    let now = Utc::now().timestamp();
    let (keys, jwt) = generate_test_jwt(
        now - MARGIN,
        now + (MARGIN + 31), // iat 61 seconds in future, so now + MARGIN < iat (61)
        now + 3600,
    );
    let mut jwt_client = JwtVerifierClient::test_client(keys.clone()).await.unwrap();
    let result = jwt_client
        .verify(
            &jwt,
            true,
            "988343938519-vle7kps2l5f6cdnjluibda25o66h2jpn.apps.googleusercontent.com",
        )
        .await;
    assert!(
        matches!(result, Err(JwtValidationError::TokenFromFuture)),
        "Token should be invalid when iat is beyond MARGIN"
    );
}
