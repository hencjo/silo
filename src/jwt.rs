use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, Header};
use rand::distributions::{Alphanumeric, DistString};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::{ResolvedConfig, UserProfile};
use crate::error::{AppError, Result};
use crate::keys::SigningKeyMaterial;
use crate::oidc::{AccessTokenResponse, TokenResponse};

#[derive(Debug, Clone)]
pub struct TokenBundle {
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Clone)]
pub struct AccessTokenBundle {
    pub access_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize)]
struct Claims {
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
    at_hash: String,
    rt_hash: String,
    sub: String,
    given_name: String,
    name: String,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

pub fn mint_token_bundle(
    signing_key: &SigningKeyMaterial,
    config: &ResolvedConfig,
    user: &UserProfile,
    client_id: &str,
    nonce: Option<&str>,
) -> Result<TokenBundle> {
    let access_token = format!("at-{}", random_token());
    let refresh_token = format!("rt-{}", random_token());
    let now = SystemTime::now();
    let iat = unix_timestamp(now)?;
    let exp = unix_timestamp(now + Duration::from_secs(config.token_ttl_seconds.max(1) as u64))?;

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(signing_key.key_id.clone());

    let extra = user.additional_claims.clone();

    let claims = Claims {
        nonce: nonce.map(ToOwned::to_owned),
        iss: config.issuer.clone(),
        aud: client_id.to_string(),
        iat,
        exp,
        at_hash: token_hash(&access_token),
        rt_hash: token_hash(&refresh_token),
        sub: user.sub.clone(),
        given_name: user.given_name.clone(),
        name: user.name.clone(),
        extra,
    };

    let id_token = jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key)?;
    Ok(TokenBundle {
        id_token,
        access_token,
        refresh_token,
    })
}

pub fn into_token_response(bundle: TokenBundle) -> TokenResponse {
    TokenResponse {
        id_token: bundle.id_token,
        access_token: bundle.access_token,
        refresh_token: bundle.refresh_token,
    }
}

#[derive(Debug, Serialize)]
struct AccessTokenClaims {
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
    sub: String,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

pub fn mint_system_access_token(
    signing_key: &SigningKeyMaterial,
    config: &ResolvedConfig,
    user: &UserProfile,
    client_id: &str,
) -> Result<AccessTokenBundle> {
    let now = SystemTime::now();
    let iat = unix_timestamp(now)?;
    let expires_in = config.token_ttl_seconds.max(1) as u64;
    let exp = unix_timestamp(now + Duration::from_secs(expires_in))?;

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(signing_key.key_id.clone());

    let extra = user.additional_claims.clone();

    let claims = AccessTokenClaims {
        iss: config.issuer.clone(),
        aud: client_id.to_string(),
        iat,
        exp,
        sub: user.sub.clone(),
        extra,
    };

    let access_token = jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key)?;
    Ok(AccessTokenBundle {
        access_token,
        expires_in,
    })
}

pub fn into_access_token_response(bundle: AccessTokenBundle) -> AccessTokenResponse {
    AccessTokenResponse {
        access_token: bundle.access_token,
        expires_in: bundle.expires_in,
    }
}

fn random_token() -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), 32)
}

fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let half = &digest[..digest.len() / 2];
    URL_SAFE_NO_PAD.encode(half)
}

fn unix_timestamp(time: SystemTime) -> Result<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| AppError::internal(err.to_string()))
}
