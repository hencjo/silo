use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, Header};
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
    pub scope: Option<String>,
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
    scope: Option<&str>,
) -> Result<TokenBundle> {
    let now = SystemTime::now();
    let iat = unix_timestamp(now)?;
    let exp = unix_timestamp(now + Duration::from_secs(config.token_ttl_seconds.max(1) as u64))?;

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(signing_key.key_id.clone());

    let extra = user.additional_claims.clone();
    let access_token_claims = AccessTokenClaims {
        iss: config.issuer.clone(),
        aud: client_id.to_string(),
        iat,
        exp,
        sub: user.sub.clone(),
        azp: Some(client_id.to_string()),
        scope: scope.map(ToOwned::to_owned),
        given_name: Some(user.given_name.clone()),
        name: Some(user.name.clone()),
        extra: extra.clone(),
    };
    let access_token =
        jsonwebtoken::encode(&header, &access_token_claims, &signing_key.encoding_key)?;

    let claims = Claims {
        nonce: nonce.map(ToOwned::to_owned),
        iss: config.issuer.clone(),
        aud: client_id.to_string(),
        iat,
        exp,
        at_hash: token_hash(&access_token),
        sub: user.sub.clone(),
        given_name: user.given_name.clone(),
        name: user.name.clone(),
        extra,
    };

    let id_token = jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key)?;
    Ok(TokenBundle {
        id_token,
        access_token,
        scope: scope.map(ToOwned::to_owned),
    })
}

pub fn into_token_response(bundle: TokenBundle) -> TokenResponse {
    TokenResponse {
        id_token: bundle.id_token,
        access_token: bundle.access_token,
        scope: bundle.scope,
    }
}

#[derive(Debug, Serialize)]
struct AccessTokenClaims {
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    azp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
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
        azp: None,
        scope: None,
        given_name: None,
        name: None,
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
