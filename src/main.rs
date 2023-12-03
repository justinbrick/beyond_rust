use core::fmt;
use ed25519_dalek::{Signature, VerifyingKey};
use std::{
    env,
    error::{self, Error},
};

use lambda_http::{http::HeaderMap, run, service_fn, Body, Request, Response};

#[derive(Debug, Clone)]
struct PublicKeyConversionError;
impl error::Error for PublicKeyConversionError {}

impl fmt::Display for PublicKeyConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Could not convert key to 32 byte array. Is the key the right size?"
        )
    }
}

#[derive(Debug, Clone)]
struct SignatureConversionError;
impl error::Error for SignatureConversionError {}

impl fmt::Display for SignatureConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Could not convert key to 64 byte array. Is the signature the right size?"
        )
    }
}

fn verify_request(headers: &HeaderMap, body: &Body) -> Result<bool, lambda_http::Error> {
    // Attempt to get the public key from environment - this can fail if Lambda is improperly configured.
    let public_key = hex::decode(env::var("BEYOND_PUBLIC_KEY")?)?
        .try_into()
        .map_err(|_| PublicKeyConversionError)?;
    let verifier = VerifyingKey::from_bytes(&public_key)?;
    // Get headers & body
    let Some(timestamp) = headers.get("X-Signature-Timestamp") else {return Ok(false)};
    let Some(signature) = headers.get("X-Signature-Ed25519") else {return Ok(false)};
    let Body::Text(body) = body else {return Ok(false)};
    // Now, validate the signature returned. If this fails, just return false instead of throwing.
    tracing::info!("We've got here!");
    let Ok(signature) = hex::decode(signature)
        .map_err(Into::into)
        .and_then(|vec| {
            <[u8; 64]>::try_from(vec)
                .map_err(|_| Box::new(SignatureConversionError) as Box<dyn Error>)
                .and_then(|bytes| Ok(Signature::from_bytes(&bytes)))
        }) else {return Ok(false)};
    // Next, we need to validate the message itself, and return the result.
    let message = [timestamp.as_bytes(), body.as_bytes()].concat();
    let result = verifier.verify_strict(message.as_slice(), &signature);
    match result {
        Ok(_) => {
            tracing::info!(name: "valid_signature", "Successfully validated signature, proceeding...");
            return Ok(true);
        }
        Err(_) => {
            tracing::info!(name: "invalid_signature", "Failed to validate message signature. Possibly discord checks...");
            return Ok(false);
        }
    }
}

async fn function_handler(event: Request) -> Result<Response<Body>, lambda_http::Error> {
    let headers = event.headers();
    let body = event.body();
    if let Body::Text(body_text) = body {
        tracing::event!(tracing::Level::INFO, body = %body_text);
    }

    if !verify_request(headers, body)? {
        let resp = Response::builder()
            .status(401)
            .body("Invalid signature".into())
            .map_err(Box::new)?;
        tracing::event!(tracing::Level::INFO, response = 401);
        return Ok(resp);
    }

    let resp = Response::builder()
        .status(200)
        .body("".into())
        .map_err(Box::new)?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    run(service_fn(function_handler)).await
}
