use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::Value;
use url::Url;

use crate::cli::ClientCredentialsArgs;
use crate::error::{AppError, Result};
use crate::oidc::normalize_scopes;

pub async fn fetch_client_credentials_token(args: ClientCredentialsArgs) -> Result<String> {
    let client = http_client(args.insecure)?;
    let issuer_url = normalize_issuer_url(&args.issuer_url);
    let client_secret = std::env::var("CLIENT_SECRET")
        .map_err(|_| AppError::bad_request("missing CLIENT_SECRET environment variable"))?;
    let discovery_url = format!("{issuer_url}/.well-known/openid-configuration");

    let discovery_response = send_and_read_json(
        "discovery",
        "GET",
        client.get(&discovery_url),
        &discovery_url,
    )
    .await?;
    let discovery_json = parse_json_response("discovery", &discovery_response)?;
    let token_endpoint = required_string_field(
        "discovery",
        "token_endpoint",
        &discovery_json,
        &discovery_response,
    )?;

    let mut token_form = vec![("grant_type", "client_credentials".to_string())];
    if let Some(scope) = normalize_scopes(&args.scope) {
        token_form.push(("scope", scope));
    }

    let token_response = send_and_read_json(
        "token",
        "POST",
        client
            .post(&token_endpoint)
            .basic_auth(args.client_id, Some(client_secret))
            .form(&token_form),
        &token_endpoint,
    )
    .await?;
    let token_json = parse_json_response("token", &token_response)?;
    let access_token =
        required_string_field("token", "access_token", &token_json, &token_response)?;
    required_u64_field("token", "expires_in", &token_json, &token_response)?;

    Ok(access_token)
}

fn http_client(insecure: bool) -> Result<Client> {
    Ok(Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()?)
}

fn normalize_issuer_url(raw: &str) -> String {
    raw.trim_end_matches('/').to_string()
}

async fn send_and_read_json(
    context: &str,
    method: &str,
    request: RequestBuilder,
    requested_url: &str,
) -> Result<RemoteResponse> {
    let response = request.send().await?;
    let status = response.status();
    let final_url = response.url().clone();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    trace_response(method, requested_url, status);
    let body = response.text().await?;
    let remote_response = RemoteResponse {
        status,
        final_url,
        content_type,
        body,
    };

    if !status.is_success() {
        return Err(AppError::bad_request(format!(
            "remote {context} request failed with status {status}{}",
            remote_response.diagnostic()
        )));
    }

    Ok(remote_response)
}

fn parse_json_response(context: &str, response: &RemoteResponse) -> Result<Value> {
    serde_json::from_str(&response.body).map_err(|error| {
        AppError::bad_request(format!(
            "remote {context} response was not valid JSON: {error}{}",
            response.diagnostic()
        ))
    })
}

fn required_string_field(
    context: &str,
    field: &str,
    json: &Value,
    response: &RemoteResponse,
) -> Result<String> {
    let value = json.get(field).and_then(Value::as_str).ok_or_else(|| {
        AppError::bad_request(format!(
            "remote {context} response did not contain string field {field}{}",
            response.diagnostic()
        ))
    })?;

    if value.is_empty() {
        return Err(AppError::bad_request(format!(
            "remote {context} response contained empty {field}{}",
            response.diagnostic()
        )));
    }

    Ok(value.to_string())
}

fn required_u64_field(
    context: &str,
    field: &str,
    json: &Value,
    response: &RemoteResponse,
) -> Result<u64> {
    json.get(field).and_then(Value::as_u64).ok_or_else(|| {
        AppError::bad_request(format!(
            "remote {context} response did not contain numeric field {field}{}",
            response.diagnostic()
        ))
    })
}

struct RemoteResponse {
    status: StatusCode,
    final_url: Url,
    content_type: Option<String>,
    body: String,
}

impl RemoteResponse {
    fn diagnostic(&self) -> String {
        format!(
            "; response: status={}, content-type={}, url={}, body={}",
            self.status,
            self.content_type.as_deref().unwrap_or("<missing>"),
            sanitized_url(&self.final_url),
            body_preview(&self.body),
        )
    }
}

fn sanitized_url(url: &Url) -> String {
    let mut url = url.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn body_preview(body: &str) -> String {
    const MAX_PREVIEW_CHARS: usize = 512;
    let body = redact_json_secrets(body).unwrap_or_else(|| redact_inline_secrets(body));
    let mut preview: String = body.chars().take(MAX_PREVIEW_CHARS).collect();
    if body.chars().nth(MAX_PREVIEW_CHARS).is_some() {
        preview.push('…');
    }
    format!("{preview:?}")
}

fn redact_json_secrets(body: &str) -> Option<String> {
    let mut json: Value = serde_json::from_str(body).ok()?;
    redact_json_value(&mut json);
    serde_json::to_string(&json).ok()
}

fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if is_secret_key(key) {
                    *value = Value::String("<redacted>".to_string());
                } else {
                    redact_json_value(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(redact_json_value),
        Value::String(value) if looks_like_jwt(value) => *value = "<redacted>".to_string(),
        _ => {}
    }
}

fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("secret")
        || key.contains("password")
        || key == "access_token"
        || key == "id_token"
        || key == "refresh_token"
        || key == "token"
}

fn redact_inline_secrets(body: &str) -> String {
    let mut redacted = String::with_capacity(body.len());
    let mut remaining = body;

    while let Some(index) = find_case_insensitive(remaining, "bearer ") {
        redacted.push_str(&remaining[..index]);
        let token = &remaining[index + "bearer ".len()..];
        let token_end = token
            .find(|character: char| character.is_whitespace() || "\"'<>&".contains(character))
            .unwrap_or(token.len());
        redacted.push_str("Bearer <redacted>");
        remaining = &token[token_end..];
    }
    redacted.push_str(remaining);
    let redacted = redact_values_after_marker(&redacted, "client_secret=");
    let redacted = redact_values_after_marker(&redacted, "client_secret:");
    redact_jwt_like_tokens(&redacted)
}

fn find_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
}

fn redact_values_after_marker(body: &str, marker: &str) -> String {
    let mut redacted = String::with_capacity(body.len());
    let mut remaining = body;

    while let Some(index) = find_case_insensitive(remaining, marker) {
        let value_start = index + marker.len();
        redacted.push_str(&remaining[..value_start]);
        let value = &remaining[value_start..];
        let value_end = value
            .find(|character: char| character.is_whitespace() || "&\"'<>,}".contains(character))
            .unwrap_or(value.len());
        redacted.push_str("<redacted>");
        remaining = &value[value_end..];
    }
    redacted.push_str(remaining);
    redacted
}

fn redact_jwt_like_tokens(body: &str) -> String {
    body.split_inclusive(|character: char| !is_jwt_character(character))
        .map(|part| {
            let token = part.trim_end_matches(|character: char| !is_jwt_character(character));
            let suffix = &part[token.len()..];
            if looks_like_jwt(token) {
                format!("<redacted>{suffix}")
            } else {
                part.to_string()
            }
        })
        .collect()
}

fn is_jwt_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
}

fn looks_like_jwt(token: &str) -> bool {
    let parts: Vec<_> = token.split('.').collect();
    parts.len() == 3 && parts.iter().all(|part| part.len() >= 8)
}

fn trace_response(method: &str, url: &str, status: StatusCode) {
    let method_color = "\x1b[36m";
    let ok_color = "\x1b[32m";
    let error_color = "\x1b[31m";
    let reset = "\x1b[0m";
    let status_color = if status.is_success() {
        ok_color
    } else {
        error_color
    };

    eprintln!("{method_color}{method:4}{reset} {url} ... {status_color}{status}{reset}");
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::{Arc, OnceLock},
    };

    use axum::{
        http::{header::CONTENT_TYPE, StatusCode},
        routing::{get, post},
        Router,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use jsonwebtoken::{decode_header, Algorithm};

    use super::{body_preview, fetch_client_credentials_token, sanitized_url};
    use crate::app::AppState;
    use crate::cli::{ClientCredentialsArgs, ServeArgs};
    use crate::config::ResolvedConfig;
    use crate::keys::load_or_create;
    use crate::server;

    fn client_secret_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    async fn with_client_secret<F, T>(future: F) -> T
    where
        F: Future<Output = T>,
    {
        let _guard = client_secret_lock().lock().await;
        std::env::set_var("CLIENT_SECRET", "client_secret");
        let result = future.await;
        std::env::remove_var("CLIENT_SECRET");
        result
    }

    async fn spawn_test_server() -> (tokio::task::JoinHandle<()>, String) {
        let yaml = r#"
clients:
  relying-party:
    client_secret: client_secret
client_credentials:
  clients:
    local-sub1:
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
        groups:
          - admin
"#;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config_file =
            std::env::temp_dir().join(format!("silo-remote-config-{}.yaml", uuid::Uuid::new_v4()));
        std::fs::write(&config_file, yaml).unwrap();
        let args = ServeArgs {
            port: addr.port(),
            config_file,
            sub: Some("sub1".to_string()),
        };

        let config = ResolvedConfig::from_serve_args(args).unwrap();
        let signing_key = load_or_create(&config.key_file).await.unwrap();
        let app: Router = server::build_router(Arc::new(AppState::new(config, signing_key)));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (handle, format!("http://localhost:{}/Silo", addr.port()))
    }

    #[tokio::test]
    async fn client_credentials_mode_fetches_remote_client_credentials_token() {
        let (handle, issuer_url) = spawn_test_server().await;

        let token = with_client_secret(async {
            fetch_client_credentials_token(ClientCredentialsArgs {
                issuer_url,
                client_id: "local-sub1".to_string(),
                scope: vec!["api.read".to_string()],
                insecure: false,
            })
            .await
            .unwrap()
        })
        .await;

        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        let payload = URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims["scope"], "api.read");
        assert_eq!(claims["groups"], serde_json::json!(["admin"]));

        handle.abort();
    }

    #[tokio::test]
    async fn client_credentials_mode_errors_on_missing_token_endpoint_field() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/issuer/.well-known/openid-configuration",
            get(|| async { axum::Json(serde_json::json!({ "issuer": "http://example.test" })) }),
        );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let error = with_client_secret(async {
            fetch_client_credentials_token(ClientCredentialsArgs {
                issuer_url: format!("http://localhost:{}/issuer", addr.port()),
                client_id: "client_id".to_string(),
                scope: Vec::new(),
                insecure: false,
            })
            .await
            .unwrap_err()
        })
        .await;

        assert!(error
            .to_string()
            .contains("remote discovery response did not contain string field token_endpoint"));

        handle.abort();
    }

    #[tokio::test]
    async fn client_credentials_mode_errors_on_missing_access_token_field() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token_endpoint = format!("http://localhost:{}/issuer/oauth2/token", addr.port());
        let app = Router::new()
            .route(
                "/issuer/.well-known/openid-configuration",
                get(move || {
                    let token_endpoint = token_endpoint.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "token_endpoint": token_endpoint
                        }))
                    }
                }),
            )
            .route(
                "/issuer/oauth2/token",
                post(|| async { axum::Json(serde_json::json!({ "expires_in": 3600 })) }),
            );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let error = with_client_secret(async {
            fetch_client_credentials_token(ClientCredentialsArgs {
                issuer_url: format!("http://localhost:{}/issuer", addr.port()),
                client_id: "client_id".to_string(),
                scope: Vec::new(),
                insecure: false,
            })
            .await
            .unwrap_err()
        })
        .await;

        assert!(error
            .to_string()
            .contains("remote token response did not contain string field access_token"));

        handle.abort();
    }

    #[tokio::test]
    async fn client_credentials_mode_errors_on_missing_expires_in_field() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token_endpoint = format!("http://localhost:{}/issuer/oauth2/token", addr.port());
        let app = Router::new()
            .route(
                "/issuer/.well-known/openid-configuration",
                get(move || {
                    let token_endpoint = token_endpoint.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "token_endpoint": token_endpoint
                        }))
                    }
                }),
            )
            .route(
                "/issuer/oauth2/token",
                post(|| async { axum::Json(serde_json::json!({ "access_token": "token" })) }),
            );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let error = with_client_secret(async {
            fetch_client_credentials_token(ClientCredentialsArgs {
                issuer_url: format!("http://localhost:{}/issuer", addr.port()),
                client_id: "client_id".to_string(),
                scope: Vec::new(),
                insecure: false,
            })
            .await
            .unwrap_err()
        })
        .await;

        assert!(error
            .to_string()
            .contains("remote token response did not contain numeric field expires_in"));

        handle.abort();
    }

    #[tokio::test]
    async fn client_credentials_mode_reports_html_token_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token_endpoint = format!("http://localhost:{}/issuer/oauth2/token", addr.port());
        let app = Router::new()
            .route(
                "/issuer/.well-known/openid-configuration",
                get(move || {
                    let token_endpoint = token_endpoint.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "token_endpoint": token_endpoint
                        }))
                    }
                }),
            )
            .route(
                "/issuer/oauth2/token",
                post(|| async { ([(CONTENT_TYPE, "text/html")], "<h1>Gateway login</h1>") }),
            );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let error = with_client_secret(async {
            fetch_client_credentials_token(ClientCredentialsArgs {
                issuer_url: format!("http://localhost:{}/issuer", addr.port()),
                client_id: "client_id".to_string(),
                scope: Vec::new(),
                insecure: false,
            })
            .await
            .unwrap_err()
        })
        .await
        .to_string();

        assert!(error.contains("remote token response was not valid JSON"));
        assert!(error.contains("status=200 OK, content-type=text/html"));
        assert!(error.contains("body=\"<h1>Gateway login</h1>\""));

        handle.abort();
    }

    #[tokio::test]
    async fn client_credentials_mode_reports_non_success_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token_endpoint = format!("http://localhost:{}/issuer/oauth2/token", addr.port());
        let app =
            Router::new()
                .route(
                    "/issuer/.well-known/openid-configuration",
                    get(move || {
                        let token_endpoint = token_endpoint.clone();
                        async move {
                            axum::Json(serde_json::json!({ "token_endpoint": token_endpoint }))
                        }
                    }),
                )
                .route(
                    "/issuer/oauth2/token",
                    post(|| async {
                        (
                            StatusCode::BAD_GATEWAY,
                            [(CONTENT_TYPE, "text/plain")],
                            "identity gateway is unavailable",
                        )
                    }),
                );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let error = with_client_secret(async {
            fetch_client_credentials_token(ClientCredentialsArgs {
                issuer_url: format!("http://localhost:{}/issuer", addr.port()),
                client_id: "client_id".to_string(),
                scope: Vec::new(),
                insecure: false,
            })
            .await
            .unwrap_err()
        })
        .await
        .to_string();

        assert!(error.contains("request failed with status 502 Bad Gateway"));
        assert!(error.contains("content-type=text/plain"));
        assert!(error.contains("body=\"identity gateway is unavailable\""));

        handle.abort();
    }

    #[test]
    fn response_preview_redacts_secrets_and_truncates_output() {
        let jwt = "abcdefgh.ijklmnop.qrstuvwx";
        let preview = body_preview(&format!(
            "Bearer opaque-token client_secret=super-secret token={jwt} {}",
            "x".repeat(600)
        ));

        assert!(preview.contains("Bearer <redacted>"));
        assert!(!preview.contains("opaque-token"));
        assert!(!preview.contains("super-secret"));
        assert!(!preview.contains(jwt));
        assert!(preview.contains('…'));
    }

    #[test]
    fn response_preview_removes_url_query_and_json_secrets() {
        let url =
            url::Url::parse("https://issuer.example/token?client_secret=secret#fragment").unwrap();
        let preview = body_preview(r#"{"access_token":"token","nested":{"password":"secret"}}"#);

        assert_eq!(sanitized_url(&url), "https://issuer.example/token");
        assert!(preview.contains("<redacted>"));
        assert!(!preview.contains("secret"));
        assert!(!preview.contains("token\""));
    }
}
