use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot};
use url::Url;

use crate::cli::AuthorizationCodeArgs;
use crate::error::{AppError, Result};
use crate::oidc::normalize_scopes;
use crate::remote;

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);
const CALLBACK_PATH: &str = "/callback";
const CALLBACK_PORT_START: u16 = 8787;
const CALLBACK_PORT_END: u16 = 8887;

#[derive(Clone)]
struct CallbackState {
    expected_state: String,
    result: mpsc::Sender<Result<String>>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn fetch_access_token(args: AuthorizationCodeArgs) -> Result<String> {
    let no_browser = args.no_browser;
    let client_secret = std::env::var("CLIENT_SECRET")
        .map_err(|_| AppError::bad_request("missing CLIENT_SECRET environment variable"))?;
    fetch_access_token_with(args, &client_secret, CALLBACK_TIMEOUT, move |url| {
        eprintln!("Open this URL to log in:\n{url}");
        if !no_browser {
            let url = url.to_string();
            std::thread::spawn(move || {
                if let Err(error) = open_browser(&url) {
                    eprintln!("Could not open browser: {error}");
                }
            });
        }
    })
    .await
}

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = std::process::Command::new("explorer.exe");
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = std::process::Command::new("xdg-open");
    #[cfg(not(any(unix, target_os = "windows")))]
    return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "opening a browser is not supported on this platform",
    ));

    let output = command.arg(url).output()?;
    if !output.stdout.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "browser opener exited with {}",
            output.status
        )));
    }
    Ok(())
}

async fn fetch_access_token_with<F>(
    args: AuthorizationCodeArgs,
    client_secret: &str,
    callback_timeout: Duration,
    on_authorization_url: F,
) -> Result<String>
where
    F: FnOnce(&Url),
{
    let listener = bind_callback_listener(CALLBACK_PORT_START, CALLBACK_PORT_END).await?;
    let callback_port = listener.local_addr()?.port();
    let redirect_uri = format!("http://localhost:{callback_port}{CALLBACK_PATH}");
    eprintln!("Redirect URI: {redirect_uri}");
    let provider =
        remote::discover_authorization_code_provider(&args.issuer_url, args.insecure).await?;
    let state = random_urlsafe_value();
    let nonce = random_urlsafe_value();
    let scope = normalize_scopes(&args.scope).unwrap_or_else(|| "openid".to_string());
    let authorization_url = build_authorization_url(
        &provider.authorization_endpoint,
        &args.client_id,
        &redirect_uri,
        &scope,
        &state,
        &nonce,
    )?;

    let (result_tx, mut result_rx) = mpsc::channel(1);
    let callback_state = CallbackState {
        expected_state: state,
        result: result_tx,
    };
    let app = Router::new()
        .route(CALLBACK_PATH, get(callback))
        .with_state(callback_state);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    on_authorization_url(&authorization_url);
    let callback_result = tokio::time::timeout(callback_timeout, result_rx.recv()).await;
    let _ = shutdown_tx.send(());
    let _ = server.await;

    let code = match callback_result {
        Ok(Some(result)) => result?,
        Ok(None) => return Err(AppError::internal("authorization callback server stopped")),
        Err(_) => {
            return Err(AppError::bad_request(format!(
                "authorization callback timed out after {} seconds",
                callback_timeout.as_secs()
            )))
        }
    };

    remote::exchange_authorization_code(
        &provider,
        &args.client_id,
        client_secret,
        &redirect_uri,
        &code,
    )
    .await
}

async fn bind_callback_listener(start: u16, end: u16) -> Result<tokio::net::TcpListener> {
    for port in start..=end {
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => return Ok(listener),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => {
                return Err(AppError::bad_request(format!(
                    "could not listen for the authorization callback on port {port}: {error}"
                )))
            }
        }
    }

    Err(AppError::bad_request(format!(
        "could not find a free authorization callback port in {start}-{end}"
    )))
}

fn build_authorization_url(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
    nonce: &str,
) -> Result<Url> {
    let mut url = Url::parse(endpoint).map_err(|error| {
        AppError::bad_request(format!(
            "discovery authorization_endpoint was not a valid URL: {error}"
        ))
    })?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", scope)
        .append_pair("state", state)
        .append_pair("nonce", nonce);
    Ok(url)
}

fn random_urlsafe_value() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn callback(
    State(state): State<CallbackState>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    if query.state.as_deref() != Some(&state.expected_state) {
        return (
            StatusCode::BAD_REQUEST,
            Html("<h1>Invalid authorization state</h1>"),
        )
            .into_response();
    }

    let result = if let Some(error) = query.error {
        let description = query
            .error_description
            .map(|value| format!(": {value}"))
            .unwrap_or_default();
        Err(AppError::bad_request(format!(
            "authorization failed: {error}{description}"
        )))
    } else if let Some(code) = query.code.filter(|code| !code.is_empty()) {
        Ok(code)
    } else {
        Err(AppError::bad_request(
            "authorization callback did not contain a code",
        ))
    };
    let success = result.is_ok();
    let _ = state.result.send(result).await;

    if success {
        (
            StatusCode::OK,
            Html("<h1>Authorization received</h1><p>You can return to the terminal.</p>"),
        )
            .into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            Html("<h1>Authorization failed</h1><p>You can return to the terminal.</p>"),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use axum::extract::{Form, Query, State};
    use axum::response::Redirect;
    use axum::routing::{get, post};
    use axum::{Json, Router};

    use super::{
        bind_callback_listener, build_authorization_url, callback, fetch_access_token_with,
        CallbackQuery, CallbackState,
    };
    use crate::cli::AuthorizationCodeArgs;

    #[test]
    fn authorization_url_preserves_endpoint_query_and_redirect() {
        let url = build_authorization_url(
            "https://idp.example/authorize?tenant=one",
            "client",
            "http://localhost:8765/callback?fixed=yes",
            "openid profile",
            "state",
            "nonce",
        )
        .unwrap();
        let pairs: Vec<_> = url.query_pairs().collect();
        assert!(pairs
            .iter()
            .any(|pair| pair == &("tenant".into(), "one".into())));
        assert!(pairs.iter().any(|pair| pair
            == &(
                "redirect_uri".into(),
                "http://localhost:8765/callback?fixed=yes".into()
            )));
        assert!(pairs
            .iter()
            .any(|pair| pair == &("scope".into(), "openid profile".into())));
    }

    #[tokio::test]
    async fn selects_the_first_free_port_in_a_range() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let start = occupied.local_addr().unwrap().port();
        assert!(start < u16::MAX);

        let listener = bind_callback_listener(start, start + 1).await.unwrap();

        assert_eq!(listener.local_addr().unwrap().port(), start + 1);
    }

    #[tokio::test]
    async fn reports_an_exhausted_callback_port_range() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = occupied.local_addr().unwrap().port();

        let error = bind_callback_listener(port, port).await.unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("could not find a free authorization callback port in {port}-{port}")
        );
    }

    #[tokio::test]
    async fn callback_rejects_wrong_state_without_finishing_login() {
        let (result, mut receiver) = tokio::sync::mpsc::channel(1);
        let response = callback(
            State(CallbackState {
                expected_state: "expected".to_string(),
                result,
            }),
            Query(CallbackQuery {
                code: Some("code".to_string()),
                state: Some("wrong".to_string()),
                error: None,
                error_description: None,
            }),
        )
        .await;

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn callback_reports_provider_errors() {
        let (result, mut receiver) = tokio::sync::mpsc::channel(1);
        let response = callback(
            State(CallbackState {
                expected_state: "expected".to_string(),
                result,
            }),
            Query(CallbackQuery {
                code: None,
                state: Some("expected".to_string()),
                error: Some("access_denied".to_string()),
                error_description: Some("Login cancelled".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let error = receiver.recv().await.unwrap().unwrap_err();
        assert_eq!(
            error.to_string(),
            "authorization failed: access_denied: Login cancelled"
        );
    }

    #[tokio::test]
    async fn completes_remote_authorization_code_flow() {
        #[derive(Clone)]
        struct ProviderState {
            base_url: String,
        }

        let provider_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider_addr = provider_listener.local_addr().unwrap();
        let base_url = format!("http://127.0.0.1:{}", provider_addr.port());
        let app = Router::new()
            .route(
                "/issuer/.well-known/openid-configuration",
                get(|State(state): State<ProviderState>| async move {
                    Json(serde_json::json!({
                        "authorization_endpoint": format!("{}/authorize?tenant=one", state.base_url),
                        "token_endpoint": format!("{}/token", state.base_url),
                    }))
                }),
            )
            .route(
                "/authorize",
                get(|Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(query.get("tenant").map(String::as_str), Some("one"));
                    assert_eq!(query.get("scope").map(String::as_str), Some("openid"));
                    let mut redirect = url::Url::parse(query.get("redirect_uri").unwrap()).unwrap();
                    assert_eq!(redirect.host_str(), Some("localhost"));
                    assert!(redirect.port().is_some_and(|port| port > 0));
                    assert_eq!(redirect.path(), "/callback");
                    redirect
                        .query_pairs_mut()
                        .append_pair("code", "one-time-code")
                        .append_pair("state", query.get("state").unwrap());
                    Redirect::temporary(redirect.as_str())
                }),
            )
            .route(
                "/token",
                post(|Form(form): Form<HashMap<String, String>>| async move {
                    assert_eq!(form.get("grant_type").map(String::as_str), Some("authorization_code"));
                    assert_eq!(form.get("client_id").map(String::as_str), Some("client"));
                    assert_eq!(form.get("client_secret").map(String::as_str), Some("secret"));
                    assert_eq!(form.get("code").map(String::as_str), Some("one-time-code"));
                    let redirect = url::Url::parse(form.get("redirect_uri").unwrap()).unwrap();
                    assert_eq!(redirect.host_str(), Some("localhost"));
                    assert!(redirect.port().is_some_and(|port| port > 0));
                    assert_eq!(redirect.path(), "/callback");
                    Json(serde_json::json!({ "access_token": "access-token" }))
                }),
            )
            .with_state(ProviderState {
                base_url: base_url.clone(),
            });
        let provider = tokio::spawn(async move {
            axum::serve(provider_listener, app).await.unwrap();
        });

        let token = fetch_access_token_with(
            AuthorizationCodeArgs {
                issuer_url: format!("{base_url}/issuer"),
                client_id: "client".to_string(),
                scope: Vec::new(),
                insecure: false,
                no_browser: true,
            },
            "secret",
            Duration::from_secs(2),
            |authorization_url| {
                let authorization_url = authorization_url.clone();
                tokio::spawn(async move {
                    reqwest::get(authorization_url).await.unwrap();
                });
            },
        )
        .await
        .unwrap();

        assert_eq!(token, "access-token");
        provider.abort();
    }

    #[tokio::test]
    async fn times_out_waiting_for_callback() {
        let provider_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider_addr = provider_listener.local_addr().unwrap();
        let authorization_endpoint = format!("http://127.0.0.1:{}/authorize", provider_addr.port());
        let token_endpoint = format!("http://127.0.0.1:{}/token", provider_addr.port());
        let app = Router::new().route(
            "/issuer/.well-known/openid-configuration",
            get(move || {
                let authorization_endpoint = authorization_endpoint.clone();
                let token_endpoint = token_endpoint.clone();
                async move {
                    Json(serde_json::json!({
                        "authorization_endpoint": authorization_endpoint,
                        "token_endpoint": token_endpoint,
                    }))
                }
            }),
        );
        let provider = tokio::spawn(async move {
            axum::serve(provider_listener, app).await.unwrap();
        });
        let error = fetch_access_token_with(
            AuthorizationCodeArgs {
                issuer_url: format!("http://127.0.0.1:{}/issuer", provider_addr.port()),
                client_id: "client".to_string(),
                scope: Vec::new(),
                insecure: false,
                no_browser: true,
            },
            "secret",
            Duration::from_millis(10),
            |_| {},
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("timed out after 0 seconds"));
        provider.abort();
    }
}
