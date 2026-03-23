use crate::codes::AuthorizationCodeStore;
use crate::config::{ResolvedConfig, UserProfile};
use crate::error::{AppError, Result};
use crate::keys::{Jwks, SigningKeyMaterial};

pub struct AppState {
    pub config: ResolvedConfig,
    pub codes: AuthorizationCodeStore,
    pub signing_key: SigningKeyMaterial,
}

impl AppState {
    pub fn new(config: ResolvedConfig, signing_key: SigningKeyMaterial) -> Self {
        Self {
            config,
            codes: AuthorizationCodeStore::new(),
            signing_key,
        }
    }

    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: vec![self.signing_key.jwk.clone()],
        }
    }

    pub fn resolve_user(&self, user_hint: Option<&str>) -> Result<Option<UserProfile>> {
        let selected_sub = user_hint
            .filter(|hint| !hint.is_empty())
            .or(self.config.selected_sub.as_deref());

        match selected_sub {
            Some(sub) if !self.config.authorization_code_users.is_empty() => self
                .config
                .authorization_code_users
                .get(sub)
                .cloned()
                .map(Some)
                .ok_or_else(|| AppError::bad_request(format!("unknown configured sub: {sub}"))),
            Some(_) => Ok(None),
            None if !self.config.authorization_code_users.is_empty() => Ok(None),
            None => Ok(self.config.default_authorization_code_user.clone()),
        }
    }

    pub fn available_users(&self) -> impl Iterator<Item = &UserProfile> {
        self.config.authorization_code_users.values()
    }

    pub fn authorization_path(&self) -> String {
        if self.config.issuer_path.is_empty() {
            "/oauth2/authorize".to_string()
        } else {
            format!("{}/oauth2/authorize", self.config.issuer_path)
        }
    }
}
