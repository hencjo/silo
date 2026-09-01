use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::cli::ServeArgs;
use crate::error::{AppError, Result};

const CLIENT_SECRET: &str = "client_secret";
const TOKEN_TTL_SECONDS: i64 = 3600;
const CODE_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone)]
pub struct UserProfile {
    pub sub: String,
    pub given_name: String,
    pub name: String,
    pub additional_claims: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub client_secret: String,
}

#[derive(Debug, Clone)]
pub struct ClientCredentialsClient {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
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
    pub authorization_code_users: Vec<UserProfile>,
    pub clients: BTreeMap<String, Client>,
    pub client_credentials_clients: BTreeMap<String, ClientCredentialsClient>,
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
        let default_authorization_code_user = match selected_sub.as_deref() {
            Some(sub) => Some(
                authorization_code_users
                    .iter()
                    .find(|user| user.sub == sub)
                    .cloned()
                    .ok_or_else(|| {
                        AppError::bad_request(format!("unknown configured sub: {sub}"))
                    })?,
            ),
            None => authorization_code_users.first().cloned(),
        };

        Ok(Self {
            listen: SocketAddr::from(([127, 0, 0, 1], args.port)),
            issuer,
            issuer_path,
            scopes_supported: supported_scopes(
                &authorization_code_users,
                &parsed.client_credentials_clients,
            ),
            key_file: parsed.key_file.unwrap_or_else(default_ephemeral_key_file),
            selected_sub,
            default_authorization_code_user,
            authorization_code_users,
            clients: parsed.clients,
            client_credentials_clients: parsed.client_credentials_clients,
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

    pub fn example_client_credentials_client(&self) -> Option<&ClientCredentialsClient> {
        self.client_credentials_clients.values().next()
    }

    pub fn authorization_code_enabled(&self) -> bool {
        !self.authorization_code_users.is_empty()
    }

    pub fn client_credentials_enabled(&self) -> bool {
        !self.client_credentials_clients.is_empty()
    }
}

pub fn example_config_yaml() -> &'static str {
    "# Example:
#   silo example-config > config.yaml
#   silo serve --port 9799 --config-file config.yaml
#
# Structure:
#   clients defines relying parties for the authorization_code flow.
#   client_credentials.clients defines machine clients and their scope-gated claims.
#   authorization_code.subs defines the selectable users for the browser flow.
#   A claims.preferred_username is shown instead of sub in the user picker.
#   Set authorization_code: {} to disable the browser flow entirely.
#   Omit client_credentials or leave its clients empty to disable that flow.
#   Each key under a requested client_credentials scope's claims becomes a JWT claim.
#   Set key_file to reuse one signing key across restarts or Silo instances.
#
# key_file: ./silo-private-key.pem
clients:
  relying-party:
    client_secret: client_secret
client_credentials:
  clients:
    system-api:
      client_secret: client_secret
      scopes:
        api.read:
          claims:
            groups:
              - admin
authorization_code:
  subs:
    sub1:
      givenName: Mock
      defaultName: Mock User
      claims:
        preferred_username: mock
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
    #[serde(default)]
    clients: BTreeMap<String, ClientConfig>,
    key_file: Option<PathBuf>,
    #[serde(default)]
    authorization_code: AuthorizationCodeConfig,
    #[serde(default)]
    client_credentials: ClientCredentialsConfig,
}

#[derive(Debug, Default, Deserialize)]
struct AuthorizationCodeConfig {
    #[serde(default)]
    subs: serde_yaml::Mapping,
}

#[derive(Debug, Deserialize)]
struct ServeSubConfig {
    #[serde(rename = "givenName")]
    given_name: String,
    #[serde(rename = "defaultName")]
    name: String,
    #[serde(default)]
    claims: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ClientConfig {
    #[serde(default = "default_client_secret")]
    client_secret: String,
}

#[derive(Debug, Default, Deserialize)]
struct ClientCredentialsConfig {
    #[serde(default)]
    clients: BTreeMap<String, ClientCredentialsClientConfig>,
}

#[derive(Debug, Deserialize)]
struct ClientCredentialsClientConfig {
    #[serde(default = "default_client_secret")]
    client_secret: String,
    #[serde(default)]
    scopes: BTreeMap<String, ClientCredentialsScopeConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct ClientCredentialsScopeConfig {
    #[serde(default)]
    claims: BTreeMap<String, serde_json::Value>,
}

struct ParsedConfigFile {
    authorization_code_users: Vec<UserProfile>,
    clients: BTreeMap<String, Client>,
    client_credentials_clients: BTreeMap<String, ClientCredentialsClient>,
    key_file: Option<PathBuf>,
}

fn load_config_file(path: &Path) -> Result<ParsedConfigFile> {
    let raw = std::fs::read_to_string(path)?;
    let parsed: ServeConfigFile = serde_yaml::from_str(&raw)?;
    let key_file = parsed.key_file.map(|key_file| {
        if key_file.is_absolute() {
            key_file
        } else {
            path.parent()
                .unwrap_or_else(|| Path::new("."))
                .join(key_file)
        }
    });
    let mut authorization_code_users = Vec::new();

    for (sub, entry) in parsed.authorization_code.subs {
        let Some(sub) = sub.as_str() else {
            return Err(AppError::bad_request(
                "authorization_code.subs keys must be strings",
            ));
        };
        let entry: ServeSubConfig = serde_yaml::from_value(entry)?;
        authorization_code_users.push(UserProfile {
            sub: sub.to_string(),
            given_name: entry.given_name,
            name: entry.name,
            additional_claims: entry.claims,
        });
    }

    let clients = parsed
        .clients
        .into_iter()
        .map(|(client_id, entry)| {
            (
                client_id,
                Client {
                    client_secret: entry.client_secret,
                },
            )
        })
        .collect();
    let client_credentials_clients = parsed
        .client_credentials
        .clients
        .into_iter()
        .map(|(client_id, entry)| {
            let scopes = entry
                .scopes
                .into_iter()
                .map(|(scope, entry)| (scope, entry.claims))
                .collect();
            (
                client_id.clone(),
                ClientCredentialsClient {
                    client_id,
                    client_secret: entry.client_secret,
                    scopes,
                },
            )
        })
        .collect();

    Ok(ParsedConfigFile {
        authorization_code_users,
        clients,
        client_credentials_clients,
        key_file,
    })
}

fn supported_scopes(
    authorization_code_users: &[UserProfile],
    client_credentials_clients: &BTreeMap<String, ClientCredentialsClient>,
) -> Vec<String> {
    let mut scopes = BTreeSet::from(["openid".to_string(), "profile".to_string()]);
    for user in authorization_code_users {
        for scope in user.additional_claims.keys() {
            scopes.insert(scope.clone());
        }
    }
    for client in client_credentials_clients.values() {
        scopes.extend(client.scopes.keys().cloned());
    }
    scopes.into_iter().collect()
}

fn default_client_secret() -> String {
    CLIENT_SECRET.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn example_config_has_yaml_comments_and_subs() {
        let yaml = example_config_yaml();
        assert!(yaml.starts_with("# Example:"));
        assert!(yaml.contains("silo example-config > config.yaml"));
        assert!(yaml.contains("clients:"));
        assert!(yaml.contains("client_credentials:"));
        assert!(yaml.contains("api.read:"));
        assert!(yaml.contains("authorization_code:"));
        assert!(yaml.contains("relying-party:"));
        assert!(yaml.contains("system-api:"));
        assert!(yaml.contains("preferred_username: mock"));
        assert!(yaml.contains("# key_file: ./silo-private-key.pem"));
    }

    #[test]
    fn parses_arbitrary_claim_values() {
        let path = std::env::temp_dir().join(format!("silo-config-{}.yaml", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            r#"
clients:
  relying-party:
    client_secret: client_secret
authorization_code:
  subs:
    sub1:
      givenName: Mock
      defaultName: Mock User
      claims:
        app00001418_groups:
          - APP00001418_sudo_all
          - APP00001418_ssh_all
        email: henrik.sjostrand@tele2.com
        enabled: true
        level: 7
"#,
        )
        .unwrap();

        let parsed = load_config_file(&path).unwrap();
        let user = parsed
            .authorization_code_users
            .iter()
            .find(|user| user.sub == "sub1")
            .unwrap();
        assert_eq!(
            user.additional_claims.get("app00001418_groups"),
            Some(&json!(["APP00001418_sudo_all", "APP00001418_ssh_all"]))
        );
        assert_eq!(
            user.additional_claims.get("email"),
            Some(&json!("henrik.sjostrand@tele2.com"))
        );
        assert_eq!(user.additional_claims.get("enabled"), Some(&json!(true)));
        assert_eq!(user.additional_claims.get("level"), Some(&json!(7)));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn parses_scope_gated_client_credentials_claims() {
        let path = std::env::temp_dir().join(format!("silo-config-{}.yaml", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            r#"
client_credentials:
  clients:
    system-api:
      client_secret: secret
      scopes:
        api.read:
          claims:
            groups:
              - reader
            enabled: true
authorization_code: {}
"#,
        )
        .unwrap();

        let parsed = load_config_file(&path).unwrap();
        assert!(parsed.clients.is_empty());
        let client = parsed.client_credentials_clients.get("system-api").unwrap();
        assert_eq!(client.client_secret, "secret");
        assert_eq!(client.scopes["api.read"]["groups"], json!(["reader"]));
        assert_eq!(client.scopes["api.read"]["enabled"], json!(true));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ignores_legacy_machine_profile_fields_under_authorization_clients() {
        let path = std::env::temp_dir().join(format!("silo-config-{}.yaml", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            r#"
clients:
  old-machine:
    client_secret: secret
    givenName: Legacy
    defaultName: Legacy Machine
    claims:
      groups:
        - admin
authorization_code: {}
"#,
        )
        .unwrap();

        let parsed = load_config_file(&path).unwrap();
        assert!(parsed.clients.contains_key("old-machine"));
        assert!(parsed.client_credentials_clients.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn preserves_authorization_code_sub_order_from_config() {
        let path = std::env::temp_dir().join(format!("silo-config-{}.yaml", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            r#"
clients:
  relying-party:
    client_secret: client_secret
authorization_code:
  subs:
    zed:
      givenName: Zed
      defaultName: Zed User
    alpha:
      givenName: Alpha
      defaultName: Alpha User
    middle:
      givenName: Middle
      defaultName: Middle User
"#,
        )
        .unwrap();

        let parsed = load_config_file(&path).unwrap();
        let subs: Vec<_> = parsed
            .authorization_code_users
            .iter()
            .map(|user| user.sub.as_str())
            .collect();
        assert_eq!(subs, ["zed", "alpha", "middle"]);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn resolves_relative_key_file_beside_config() {
        let directory = std::env::temp_dir().join(format!("silo-config-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let config_file = directory.join("silo.yaml");
        std::fs::write(
            &config_file,
            r#"
key_file: keys/shared.pem
clients:
  relying-party:
    client_secret: client_secret
authorization_code: {}
"#,
        )
        .unwrap();

        let config = ResolvedConfig::from_serve_args(ServeArgs {
            port: 9393,
            config_file,
            sub: None,
        })
        .unwrap();

        assert_eq!(config.key_file, directory.join("keys/shared.pem"));
        let _ = std::fs::remove_dir_all(directory);
    }
}
