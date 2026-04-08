use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::cli::ServeArgs;
use crate::error::{AppError, Result};

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
pub struct Client {
    pub client_id: String,
    pub client_secret: String,
    pub profile: UserProfile,
    pub explicit_client_credentials_profile: bool,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub listen: SocketAddr,
    pub issuer: String,
    pub issuer_path: String,
    pub scopes_supported: Vec<String>,
    pub key_file: PathBuf,
    pub selected_sub: Option<String>,
    pub default_authorization_code_user: Option<UserProfile>,
    pub authorization_code_users: BTreeMap<String, UserProfile>,
    pub clients: BTreeMap<String, Client>,
    pub token_ttl_seconds: i64,
    pub code_ttl_seconds: i64,
}

impl ResolvedConfig {
    pub fn from_serve_args(args: ServeArgs) -> Result<Self> {
        let issuer = default_issuer(args.port);
        let issuer_path = issuer_path(&issuer)?;
        let parsed = load_config_file(&args.config_file)?;
        let authorization_code_users = parsed.authorization_code_users;
        let selected_sub = args.sub.clone();
        let default_authorization_code_user =
            match selected_sub.as_deref() {
                Some(sub) => Some(authorization_code_users.get(sub).cloned().ok_or_else(|| {
                    AppError::bad_request(format!("unknown configured sub: {sub}"))
                })?),
                None => authorization_code_users.values().next().cloned(),
            };

        Ok(Self {
            listen: SocketAddr::from(([127, 0, 0, 1], args.port)),
            issuer,
            issuer_path,
            scopes_supported: supported_scopes(&authorization_code_users, &parsed.clients),
            key_file: default_ephemeral_key_file(),
            selected_sub,
            default_authorization_code_user,
            authorization_code_users,
            clients: parsed.clients,
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

    pub fn example_client_credentials_client(&self) -> Option<&Client> {
        self.clients
            .values()
            .find(|client| client.explicit_client_credentials_profile)
            .or_else(|| self.clients.values().next())
    }

    pub fn authorization_code_enabled(&self) -> bool {
        !self.authorization_code_users.is_empty()
    }
}

pub fn key_id() -> &'static str {
    KEY_ID
}

pub fn example_config_yaml() -> &'static str {
    "# Example:
#   silo example-config > config.yaml
#   silo serve --port 9799 --config-file config.yaml
#
# Structure:
#   clients maps OAuth client ids to their client_secret and optional client_credentials claims.
#   All entries under clients are clients, and any client_id may use any flow.
#   authorization_code.subs defines the selectable users for the browser flow.
#   Set authorization_code: {} to disable the browser flow entirely.
#   Each key under claims becomes a claim in the issued JWT.
#
clients:
  relying-party:
    client_secret: client_secret
  system-api:
    client_secret: client_secret
    givenName: System
    defaultName: System API
    claims:
      groups:
        - admin
authorization_code:
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
    normalized_issuer(&format!("http://localhost:{port}/Silo"))
}

fn default_ephemeral_key_file() -> PathBuf {
    std::env::temp_dir().join(format!("silo-{}.pem", uuid::Uuid::new_v4()))
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
    clients: BTreeMap<String, ClientConfig>,
    #[serde(default)]
    authorization_code: AuthorizationCodeConfig,
}

#[derive(Debug, Default, Deserialize)]
struct AuthorizationCodeConfig {
    #[serde(default)]
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

#[derive(Debug, Deserialize)]
struct ClientConfig {
    #[serde(default = "default_client_secret")]
    client_secret: String,
    #[serde(rename = "givenName")]
    given_name: Option<String>,
    #[serde(rename = "defaultName")]
    name: Option<String>,
    #[serde(default)]
    claims: BTreeMap<String, Vec<String>>,
}

struct ParsedConfigFile {
    authorization_code_users: BTreeMap<String, UserProfile>,
    clients: BTreeMap<String, Client>,
}

fn load_config_file(path: &Path) -> Result<ParsedConfigFile> {
    let raw = std::fs::read_to_string(path)?;
    let parsed: ServeConfigFile = serde_yaml::from_str(&raw)?;
    let mut authorization_code_users = BTreeMap::new();

    for (sub, entry) in parsed.authorization_code.subs {
        authorization_code_users.insert(
            sub.clone(),
            UserProfile {
                sub,
                given_name: entry.given_name,
                name: entry.name,
                additional_claims: entry.claims,
            },
        );
    }

    let mut clients = BTreeMap::new();
    for (client_id, entry) in parsed.clients {
        let explicit_profile =
            entry.given_name.is_some() || entry.name.is_some() || !entry.claims.is_empty();
        let given_name = entry.given_name.unwrap_or_else(|| client_id.clone());
        let name = entry.name.unwrap_or_else(|| client_id.clone());
        clients.insert(
            client_id.clone(),
            Client {
                client_id: client_id.clone(),
                client_secret: entry.client_secret,
                profile: UserProfile {
                    sub: client_id,
                    given_name,
                    name,
                    additional_claims: entry.claims,
                },
                explicit_client_credentials_profile: explicit_profile,
            },
        );
    }

    Ok(ParsedConfigFile {
        authorization_code_users,
        clients,
    })
}

fn supported_scopes(
    authorization_code_users: &BTreeMap<String, UserProfile>,
    clients: &BTreeMap<String, Client>,
) -> Vec<String> {
    let mut scopes = BTreeSet::from(["openid".to_string(), "profile".to_string()]);
    for user in authorization_code_users.values() {
        for scope in user.additional_claims.keys() {
            scopes.insert(scope.clone());
        }
    }
    for client in clients.values() {
        for scope in client.profile.additional_claims.keys() {
            scopes.insert(scope.clone());
        }
    }
    scopes.into_iter().collect()
}

fn default_client_secret() -> String {
    CLIENT_SECRET.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_has_yaml_comments_and_subs() {
        let yaml = example_config_yaml();
        assert!(yaml.starts_with("# Example:"));
        assert!(yaml.contains("silo example-config > config.yaml"));
        assert!(yaml.contains("clients:"));
        assert!(yaml.contains("authorization_code:"));
        assert!(yaml.contains("relying-party:"));
        assert!(yaml.contains("system-api:"));
    }
}
