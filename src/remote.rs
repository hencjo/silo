use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::Value;

use crate::cli::ClientCredentialsArgs;
use crate::error::{AppError, Result};

pub async fn fetch_client_credentials_token(args: ClientCredentialsArgs) -> Result<String> {
    let client = http_client(args.insecure)?;
    let issuer_url = normalize_issuer_url(&args.issuer_url);
    let client_secret = std::env::var("CLIENT_SECRET")
        .map_err(|_| AppError::bad_request("missing CLIENT_SECRET environment variable"))?;
    let discovery_url = format!("{issuer_url}/.well-known/openid-configuration");

    let discovery_body = send_and_read_json(
        "discovery",
        "GET",
        client.get(&discovery_url),
        &discovery_url,
    )
    .await?;
    let discovery_json = parse_json_response("discovery", &discovery_body)?;
    let token_endpoint = required_string_field("discovery", "token_endpoint", &discovery_json)?;

    let token_body = send_and_read_json(
        "token",
        "POST",
        client
            .post(&token_endpoint)
            .basic_auth(args.client_id, Some(client_secret))
            .form(&[("grant_type", "client_credentials")]),
        &token_endpoint,
    )
    .await?;
    let token_json = parse_json_response("token", &token_body)?;
    let access_token = required_string_field("token", "access_token", &token_json)?;
    required_u64_field("token", "expires_in", &token_json)?;

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
) -> Result<String> {
    let response = request.send().await?;
    let status = response.status();
    trace_response(method, requested_url, status);
    let body = response.text().await?;

    if !status.is_success() {
        return Err(AppError::bad_request(format!(
            "remote {context} request failed with status {status}"
        )));
    }

    Ok(body)
}

fn parse_json_response(context: &str, body: &str) -> Result<Value> {
    serde_json::from_str(body).map_err(|error| {
        AppError::bad_request(format!(
            "remote {context} response was not valid JSON: {error}"
        ))
    })
}

fn required_string_field(context: &str, field: &str, json: &Value) -> Result<String> {
    let value = json.get(field).and_then(Value::as_str).ok_or_else(|| {
        AppError::bad_request(format!(
            "remote {context} response did not contain string field {field}"
        ))
    })?;

    if value.is_empty() {
        return Err(AppError::bad_request(format!(
            "remote {context} response contained empty {field}"
        )));
    }

    Ok(value.to_string())
}

fn required_u64_field(context: &str, field: &str, json: &Value) -> Result<u64> {
    json.get(field).and_then(Value::as_u64).ok_or_else(|| {
        AppError::bad_request(format!(
            "remote {context} response did not contain numeric field {field}"
        ))
    })
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
        routing::{get, post},
        Router,
    };
    use jsonwebtoken::{decode_header, Algorithm};

    use super::fetch_client_credentials_token;
    use crate::app::AppState;
    use crate::cli::{ClientCredentialsArgs, KeyArgs, ServeArgs};
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
        let temp =
            std::env::temp_dir().join(format!("niloo-remote-test-{}.pem", uuid::Uuid::new_v4()));
        let config_file =
            std::env::temp_dir().join(format!("niloo-remote-config-{}.yaml", uuid::Uuid::new_v4()));
        std::fs::write(&config_file, yaml).unwrap();
        let args = ServeArgs {
            keys: KeyArgs {
                key_file: Some(temp),
            },
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
        (handle, format!("http://localhost:{}/Niloo", addr.port()))
    }

    #[tokio::test]
    async fn client_credentials_mode_fetches_remote_client_credentials_token() {
        let (handle, issuer_url) = spawn_test_server().await;

        let token = with_client_secret(async {
            fetch_client_credentials_token(ClientCredentialsArgs {
                issuer_url,
                client_id: "sub1".to_string(),
                insecure: false,
            })
            .await
            .unwrap()
        })
        .await;

        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);

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
}
