use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::UserProfile;
use crate::error::{AppError, Result};

#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub nonce: String,
    pub scope: Option<String>,
    pub user: UserProfile,
    pub expires_at: SystemTime,
}

#[derive(Debug, Default)]
pub struct AuthorizationCodeStore {
    inner: RwLock<HashMap<String, AuthorizationCode>>,
}

impl AuthorizationCodeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn issue(&self, payload: AuthorizationCode) -> String {
        let code = format!("code-{}", Uuid::new_v4());
        self.inner.write().await.insert(code.clone(), payload);
        code
    }

    pub async fn consume(
        &self,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
    ) -> Result<AuthorizationCode> {
        let payload = self
            .inner
            .write()
            .await
            .remove(code)
            .ok_or_else(|| AppError::bad_request("unknown authorization code"))?;

        if payload.expires_at <= SystemTime::now() {
            return Err(AppError::bad_request("authorization code expired"));
        }
        if payload.redirect_uri != redirect_uri {
            return Err(AppError::bad_request(
                "redirect_uri does not match authorization code",
            ));
        }
        if payload.client_id != client_id {
            return Err(AppError::bad_request(
                "client_id does not match authorization code",
            ));
        }
        Ok(payload)
    }
}

pub fn expiration_after(seconds: i64) -> SystemTime {
    let seconds = seconds.max(1) as u64;
    SystemTime::now() + Duration::from_secs(seconds)
}
