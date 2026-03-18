use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::cli::ServeArgs;
use crate::error::{AppError, Result};

const CLIENT_ID: &str = "client_id";
const CLIENT_SECRET: &str = "client_secret";
const KEY_ID: &str = "kid-local-rsa-1";
const TOKEN_TTL_SECONDS: i64 = 3600;
const CODE_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone)]
pub struct UserProfile {
    pub sub: String,
    pub given_name: String,
    pub name: String,
    pub additional_claims: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub listen: SocketAddr,
    pub issuer: String,
    pub issuer_path: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes_supported: Vec<String>,
    pub key_file: PathBuf,
    pub selected_sub: Option<String>,
    pub default_user: UserProfile,
    pub users: BTreeMap<String, UserProfile>,
    pub token_ttl_seconds: i64,
    pub code_ttl_seconds: i64,
}

impl ResolvedConfig {
    pub fn from_serve_args(args: ServeArgs) -> Result<Self> {
        let issuer = default_issuer(args.port);
        let issuer_path = issuer_path(&issuer)?;
        let users = load_users_from_file(&args.config_file)?;
        let selected_sub = args.sub.clone();
        let default_user =
            match selected_sub.as_deref() {
                Some(sub) => users.get(sub).cloned().ok_or_else(|| {
                    AppError::bad_request(format!("unknown configured sub: {sub}"))
                })?,
                None => users.values().next().cloned().ok_or_else(|| {
                    AppError::bad_request("config file must define at least one sub")
                })?,
            };

        Ok(Self {
            listen: SocketAddr::from(([127, 0, 0, 1], args.port)),
            issuer,
            issuer_path,
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
            scopes_supported: supported_scopes(&users),
            key_file: args
                .keys
                .key_file
                .unwrap_or_else(default_ephemeral_key_file),
            selected_sub,
            default_user,
            users,
            token_ttl_seconds: TOKEN_TTL_SECONDS,
            code_ttl_seconds: CODE_TTL_SECONDS,
        })
    }

    pub fn authorization_endpoint(&self) -> String {
        format!("{}{}", self.issuer, "/oauth2/authorize")
    }

    pub fn token_endpoint(&self) -> String {
        format!("{}{}", self.issuer, "/oauth2/token")
    }

    pub fn jwks_uri(&self) -> String {
        format!("{}{}", self.issuer, "/jwks.json")
    }

    pub fn example_client_credentials_client_id(&self) -> Option<&str> {
        self.selected_sub
            .as_deref()
            .or_else(|| self.users.keys().next().map(String::as_str))
    }
}

pub fn key_id() -> &'static str {
    KEY_ID
}

pub fn example_config_yaml() -> &'static str {
    "# Example:
#   niloo example-config > config.yaml
#   niloo serve --port 9799 --config-file config.yaml
#
# Structure:
#   subs maps each selectable subject id to display names and extra token claims.
#   Each key under claims becomes a claim in the issued JWT.
#
subs:
  sub1:
    givenName: Mock
    defaultName: Mock User
    claims:
      groups:
        - admin
  sub2:
    givenName: Admin
    defaultName: Admin User
    claims:
      groups:
        - auditor
"
}

fn default_issuer(port: u16) -> String {
    normalized_issuer(&format!("http://localhost:{port}/Niloo"))
}

fn default_ephemeral_key_file() -> PathBuf {
    std::env::temp_dir().join(format!("niloo-{}.pem", uuid::Uuid::new_v4()))
}

fn normalized_issuer(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        raw.to_string()
    } else {
        trimmed.to_string()
    }
}

fn issuer_path(raw: &str) -> Result<String> {
    let parsed = url::Url::parse(raw)?;
    let path = parsed.path().trim_end_matches('/');
    Ok(if path.is_empty() || path == "/" {
        String::new()
    } else {
        path.to_string()
    })
}

#[derive(Debug, Deserialize)]
struct ServeConfigFile {
    subs: BTreeMap<String, ServeSubConfig>,
}

#[derive(Debug, Deserialize)]
struct ServeSubConfig {
    #[serde(rename = "givenName")]
    given_name: String,
    #[serde(rename = "defaultName")]
    name: String,
    #[serde(default)]
    claims: BTreeMap<String, Vec<String>>,
}

fn load_users_from_file(path: &Path) -> Result<BTreeMap<String, UserProfile>> {
    let raw = std::fs::read_to_string(path)?;
    let parsed: ServeConfigFile = serde_yaml::from_str(&raw)?;
    let mut users = BTreeMap::new();

    for (sub, entry) in parsed.subs {
        users.insert(
            sub.clone(),
            UserProfile {
                sub,
                given_name: entry.given_name,
                name: entry.name,
                additional_claims: entry.claims,
            },
        );
    }

    Ok(users)
}

fn supported_scopes(users: &BTreeMap<String, UserProfile>) -> Vec<String> {
    let mut scopes = BTreeSet::from(["openid".to_string(), "profile".to_string()]);
    for user in users.values() {
        for scope in user.additional_claims.keys() {
            scopes.insert(scope.clone());
        }
    }
    scopes.into_iter().collect()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_has_yaml_comments_and_subs() {
        let yaml = example_config_yaml();
        assert!(yaml.starts_with("# Example:"));
        assert!(yaml.contains("niloo example-config > config.yaml"));
        assert!(yaml.contains("subs:"));
        assert!(yaml.contains("givenName: Mock"));
    }
}
