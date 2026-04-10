use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tower_http::trace::TraceLayer;
use url::Url;

use crate::app::AppState;
use crate::codes::{expiration_after, AuthorizationCode};
use crate::error::{AppError, Result};
use crate::jwt;
use crate::oidc::{AuthorizationQuery, DiscoveryDocument, TokenForm};

pub fn build_router(state: Arc<AppState>) -> Router {
    let issuer_path = state.config.issuer_path.clone();

    Router::new()
        .route(
            &route_path(&issuer_path, "/.well-known/openid-configuration"),
            get(discovery),
        )
        .route(
            &route_path(&issuer_path, "/oauth2/authorize"),
            get(authorize),
        )
        .route(&route_path(&issuer_path, "/oauth2/token"), post(token))
        .route(&route_path(&issuer_path, "/jwks.json"), get(jwks))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn route_path(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        suffix.to_string()
    } else {
        format!("{prefix}{suffix}")
    }
}

async fn discovery(State(state): State<Arc<AppState>>) -> Json<DiscoveryDocument> {
    let mut grant_types_supported = vec!["client_credentials".to_string()];
    if state.config.authorization_code_enabled() {
        grant_types_supported.insert(0, "authorization_code".to_string());
    }

    Json(DiscoveryDocument {
        issuer: state.config.issuer.clone(),
        authorization_endpoint: state.config.authorization_endpoint(),
        token_endpoint: state.config.token_endpoint(),
        jwks_uri: state.config.jwks_uri(),
        scopes_supported: state.config.scopes_supported.clone(),
        grant_types_supported,
    })
}

async fn authorize(State(state): State<Arc<AppState>>, raw_query: RawQuery) -> Result<Response> {
    if !state.config.authorization_code_enabled() {
        return Err(AppError::bad_request("authorization_code flow is disabled"));
    }

    let query = AuthorizationQuery::parse(raw_query.0.as_deref())?;

    if query.response_type != "code" {
        return Err(AppError::bad_request("response_type must be code"));
    }
    if !state.config.clients.contains_key(&query.client_id) {
        return Err(AppError::unauthorized("unexpected client_id"));
    }
    if query.state.is_empty() || query.redirect_uri.is_empty() || query.nonce.is_empty() {
        return Err(AppError::bad_request(
            "state, redirect_uri, and nonce are required",
        ));
    }

    let user_hint = query.mock_user.as_deref().or(query.login_hint.as_deref());
    let user = match state.resolve_user(user_hint)? {
        Some(user) => user,
        None => {
            let html =
                render_user_selection_page(&state, raw_query.0.as_deref().unwrap_or_default());
            return Ok((StatusCode::OK, Html(html)).into_response());
        }
    };

    let code = state
        .codes
        .issue(AuthorizationCode {
            client_id: query.client_id,
            redirect_uri: query.redirect_uri.clone(),
            nonce: query.nonce,
            user,
            expires_at: expiration_after(state.config.code_ttl_seconds),
        })
        .await;

    let mut redirect = Url::parse(&query.redirect_uri)?;
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs.append_pair("code", &code);
        pairs.append_pair("state", &query.state);
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(redirect.as_ref())
            .map_err(|err| AppError::internal(err.to_string()))?,
    );
    Ok((StatusCode::FOUND, headers).into_response())
}

async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<Response> {
    match form.grant_type.as_str() {
        "authorization_code" => authorization_code_token(state, form).await,
        "client_credentials" => client_credentials_token(state, headers, form).await,
        _ => Err(AppError::bad_request(
            "grant_type must be authorization_code or client_credentials",
        )),
    }
}

async fn jwks(State(state): State<Arc<AppState>>) -> Json<crate::keys::Jwks> {
    Json(state.jwks())
}

async fn authorization_code_token(state: Arc<AppState>, form: TokenForm) -> Result<Response> {
    if !state.config.authorization_code_enabled() {
        return Err(AppError::bad_request("authorization_code flow is disabled"));
    }

    let client_id = required_form_field("client_id", form.client_id)?;
    let client_secret = required_form_field("client_secret", form.client_secret)?;
    let redirect_uri = required_form_field("redirect_uri", form.redirect_uri)?;
    let code = required_form_field("code", form.code)?;

    let client = state
        .config
        .clients
        .get(&client_id)
        .ok_or_else(|| AppError::unauthorized("invalid client credentials"))?;

    if client_secret != client.client_secret {
        return Err(AppError::unauthorized("invalid client credentials"));
    }

    let code = state
        .codes
        .consume(&code, &redirect_uri, &client_id)
        .await?;

    let bundle = jwt::mint_token_bundle(
        &state.signing_key,
        &state.config,
        &code.user,
        &client_id,
        Some(&code.nonce),
    )?;

    Ok(Json(jwt::into_token_response(bundle)).into_response())
}

async fn client_credentials_token(
    state: Arc<AppState>,
    headers: HeaderMap,
    form: TokenForm,
) -> Result<Response> {
    let client_id = validate_basic_authorization(&headers, &state)?;

    if form.client_id.is_some()
        || form.client_secret.is_some()
        || form.redirect_uri.is_some()
        || form.code.is_some()
    {
        log_client_credentials_failure(
            &state,
            StatusCode::BAD_REQUEST,
            "unexpected form fields",
            Some(&client_id),
            None,
        );
        return Err(AppError::bad_request(
            "client_credentials does not accept client_id, client_secret, redirect_uri, or code form fields",
        ));
    }

    let machine_client = state
        .config
        .clients
        .get(&client_id)
        .cloned()
        .ok_or_else(|| {
            log_client_credentials_failure(
                &state,
                StatusCode::UNAUTHORIZED,
                "unknown client_id",
                Some(&client_id),
                Some(&expected_client_credentials_hint(&state)),
            );
            AppError::unauthorized("unknown client_id")
        })?;

    let bundle = jwt::mint_system_access_token(
        &state.signing_key,
        &state.config,
        &machine_client.profile,
        &client_id,
    )?;

    Ok(Json(jwt::into_access_token_response(bundle)).into_response())
}

fn required_form_field(name: &str, value: Option<String>) -> Result<String> {
    value.ok_or_else(|| AppError::bad_request(format!("missing form field: {name}")))
}

fn validate_basic_authorization(headers: &HeaderMap, state: &AppState) -> Result<String> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| {
            log_client_credentials_failure(
                state,
                StatusCode::UNAUTHORIZED,
                "missing Authorization header",
                None,
                Some(&expected_client_credentials_hint(state)),
            );
            AppError::unauthorized("missing Authorization header")
        })?
        .to_str()
        .map_err(|err| {
            log_client_credentials_failure(
                state,
                StatusCode::BAD_REQUEST,
                "invalid Authorization header",
                None,
                Some(&expected_client_credentials_hint(state)),
            );
            AppError::bad_request(err.to_string())
        })?;

    let encoded = authorization.strip_prefix("Basic ").ok_or_else(|| {
        log_client_credentials_failure(
            state,
            StatusCode::UNAUTHORIZED,
            "invalid Authorization header",
            None,
            Some(&expected_client_credentials_hint(state)),
        );
        AppError::unauthorized("invalid Authorization header")
    })?;
    let decoded = STANDARD.decode(encoded).map_err(|_| {
        log_client_credentials_failure(
            state,
            StatusCode::UNAUTHORIZED,
            "invalid Authorization header",
            None,
            Some(&expected_client_credentials_hint(state)),
        );
        AppError::unauthorized("invalid Authorization header")
    })?;
    let decoded = String::from_utf8(decoded).map_err(|_| {
        log_client_credentials_failure(
            state,
            StatusCode::UNAUTHORIZED,
            "invalid Authorization header",
            None,
            Some(&expected_client_credentials_hint(state)),
        );
        AppError::unauthorized("invalid Authorization header")
    })?;
    let (client_id, client_secret) = decoded.split_once(':').ok_or_else(|| {
        log_client_credentials_failure(
            state,
            StatusCode::UNAUTHORIZED,
            "invalid Authorization header",
            None,
            Some(&expected_client_credentials_hint(state)),
        );
        AppError::unauthorized("invalid Authorization header")
    })?;

    let expected_secret = state
        .config
        .clients
        .get(client_id)
        .map(|client| client.client_secret.as_str());

    let Some(expected_secret) = expected_secret else {
        return Ok(client_id.to_string());
    };

    if client_secret != expected_secret {
        log_client_credentials_failure(
            state,
            StatusCode::UNAUTHORIZED,
            "invalid client_secret",
            Some(client_id),
            Some(&expected_client_secret_hint(client_id, expected_secret)),
        );
        return Err(AppError::unauthorized("invalid Authorization header"));
    }

    Ok(client_id.to_string())
}

fn log_client_credentials_failure(
    state: &AppState,
    status: StatusCode,
    reason: &str,
    client_id: Option<&str>,
    hint: Option<&str>,
) {
    let color = if status.is_client_error() {
        "\x1b[33m"
    } else {
        "\x1b[31m"
    };
    let reset = "\x1b[0m";
    let path = route_path(&state.config.issuer_path, "/oauth2/token");

    match (client_id, hint) {
        (Some(client_id), Some(hint)) => eprintln!(
            "{color}{status}{reset} client_credentials {path} {reason} client_id={client_id} {hint}"
        ),
        (Some(client_id), None) => eprintln!(
            "{color}{status}{reset} client_credentials {path} {reason} client_id={client_id}"
        ),
        (None, Some(hint)) => {
            eprintln!("{color}{status}{reset} client_credentials {path} {reason} {hint}")
        }
        (None, None) => eprintln!("{color}{status}{reset} client_credentials {path} {reason}"),
    }
}

fn expected_client_credentials_hint(state: &AppState) -> String {
    let client_ids = if state.config.clients.is_empty() {
        "none".to_string()
    } else {
        state
            .config
            .clients
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!("expected_client_id=[{client_ids}]")
}

fn expected_client_secret_hint(client_id: &str, client_secret: &str) -> String {
    format!("expected_client_id={client_id} expected_client_secret={client_secret}")
}

fn render_user_selection_page(state: &AppState, raw_query: &str) -> String {
    let items = state
        .available_users()
        .map(|user| {
            let href = chooser_href(&state.authorization_path(), raw_query, &user.sub);
            format!(
                "<li><a href=\"{}\">{} <span>{}</span></a></li>",
                escape_html(&href),
                escape_html(&user.sub),
                escape_html(&user.name)
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>SILO: Silo is local OpenID</title><style>body{{margin:0;background:#111;color:#f5f5f5;font:16px/1.5 monospace}}main{{max-width:720px;margin:0 auto;padding:32px 20px}}section{{border:1px solid #444;background:#1a1a1a;padding:20px}}h1{{margin:0 0 8px;font-size:28px}}p{{margin:0 0 20px;color:#cfcfcf}}ul{{list-style:none;padding:0;margin:0;border-top:1px solid #333}}li{{border-bottom:1px solid #333}}a{{display:flex;justify-content:space-between;gap:16px;padding:14px 0;color:#fff;text-decoration:none}}a:hover,a:focus{{background:#222;outline:none}}span{{color:#a3a3a3}}</style></head><body><main><section><h1>SILO: Silo is local OpenID</h1><p>Select a user to continue.</p><ul>{items}</ul></section></main><script>const items=[...document.querySelectorAll('a')];if(items.length)items[0].focus();document.addEventListener('keydown',e=>{{if(e.key!=='ArrowDown'&&e.key!=='ArrowUp')return;const i=Math.max(items.indexOf(document.activeElement),0);const n=e.key==='ArrowDown'?Math.min(i+1,items.length-1):Math.max(i-1,0);items[n]?.focus();e.preventDefault();}});</script></body></html>"
    )
}

fn chooser_href(path: &str, raw_query: &str, sub: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        if key != "mock_user" {
            serializer.append_pair(&key, &value);
        }
    }
    serializer.append_pair("mock_user", sub);
    format!("{path}?{}", serializer.finish())
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request, StatusCode};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
    use tower::util::ServiceExt;

    use crate::app::AppState;
    use crate::cli::ServeArgs;
    use crate::config::ResolvedConfig;
    use crate::keys::load_or_create;

    async fn test_app(selected_sub: Option<&str>) -> axum::Router {
        let yaml = r#"
clients:
  relying-party:
    client_secret: client_secret
  local-sub2:
    client_secret: client_secret
    givenName: Admin
    defaultName: Admin User
    claims:
      groups:
        - auditor
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
        email: admin@example.com
"#;
        let config_file =
            std::env::temp_dir().join(format!("silo-config-{}.yaml", uuid::Uuid::new_v4()));
        std::fs::write(&config_file, yaml).unwrap();
        let args = ServeArgs {
            port: 9393,
            config_file,
            sub: selected_sub.map(ToOwned::to_owned),
        };

        let config = ResolvedConfig::from_serve_args(args).unwrap();
        let signing_key = load_or_create(&config.key_file).await.unwrap();
        crate::server::build_router(Arc::new(AppState::new(config, signing_key)))
    }

    async fn test_app_with_yaml(yaml: &str, selected_sub: Option<&str>) -> axum::Router {
        let config_file =
            std::env::temp_dir().join(format!("silo-config-{}.yaml", uuid::Uuid::new_v4()));
        std::fs::write(&config_file, yaml).unwrap();
        let args = ServeArgs {
            port: 9393,
            config_file,
            sub: selected_sub.map(ToOwned::to_owned),
        };

        let config = ResolvedConfig::from_serve_args(args).unwrap();
        let signing_key = load_or_create(&config.key_file).await.unwrap();
        crate::server::build_router(Arc::new(AppState::new(config, signing_key)))
    }

    #[tokio::test]
    async fn serves_root_discovery_document() {
        let app = test_app(None).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/Silo/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["issuer"], "http://localhost:9393/Silo");
        assert_eq!(
            json["authorization_endpoint"],
            "http://localhost:9393/Silo/oauth2/authorize"
        );
        assert_eq!(
            json["scopes_supported"],
            serde_json::json!(["email", "groups", "openid", "profile"])
        );
        assert_eq!(
            json["grant_types_supported"],
            serde_json::json!(["authorization_code", "client_credentials"])
        );
    }

    #[tokio::test]
    async fn omits_authorization_code_from_discovery_when_disabled() {
        let app = test_app_with_yaml(
            r#"
clients:
  relying-party:
    client_secret: client_secret
authorization_code: {}
"#,
            None,
        )
        .await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/Silo/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["grant_types_supported"],
            serde_json::json!(["client_credentials"])
        );
    }

    #[tokio::test]
    async fn presents_user_selection_page_when_no_default_sub_is_configured() {
        let app = test_app(None).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/Silo/oauth2/authorize?response_type=code&client_id=relying-party&redirect_uri=http://localhost:8080/oauth&nonce=test-nonce&state=test-state")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("SILO: Silo is local OpenID"));
        assert!(html.contains("Select a user to continue."));
        assert!(html.contains("mock_user=sub1"));
        assert!(html.contains("mock_user=sub2"));
    }

    #[tokio::test]
    async fn rejects_authorize_when_authorization_code_is_disabled() {
        let app = test_app_with_yaml(
            r#"
clients:
  relying-party:
    client_secret: client_secret
authorization_code: {}
"#,
            None,
        )
        .await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/Silo/oauth2/authorize?response_type=code&client_id=relying-party&redirect_uri=http://localhost:8080/oauth&nonce=test-nonce&state=test-state")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_system_access_token_for_client_credentials() {
        let app = test_app(Some("sub2")).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/Silo/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("authorization", basic_authorization("local-sub2"))
                    .body(Body::from("grant_type=client_credentials"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("id_token").is_none());
        assert!(json.get("refresh_token").is_none());
        assert_eq!(json["expires_in"], 3600);

        let access_token = json["access_token"].as_str().unwrap();
        let header = decode_header(access_token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some(crate::config::key_id()));

        let jwks = app
            .oneshot(
                Request::builder()
                    .uri("/Silo/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let jwks_body = to_bytes(jwks.into_body(), usize::MAX).await.unwrap();
        let jwks_json: serde_json::Value = serde_json::from_slice(&jwks_body).unwrap();
        let key = &jwks_json["keys"][0];
        let decoding_key = DecodingKey::from_rsa_components(
            key["n"].as_str().unwrap(),
            key["e"].as_str().unwrap(),
        )
        .unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["local-sub2"]);
        validation.set_issuer(&["http://localhost:9393/Silo"]);

        let claims = decode::<serde_json::Value>(access_token, &decoding_key, &validation).unwrap();
        assert_eq!(claims.claims["sub"], "local-sub2");
        assert_eq!(claims.claims["groups"][0], "auditor");
        assert!(claims.claims.get("nonce").is_none());
    }

    #[tokio::test]
    async fn rejects_client_credentials_without_basic_authorization() {
        let app = test_app(Some("sub1")).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/Silo/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=client_credentials"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_client_credentials_for_unknown_client_id() {
        let app = test_app(Some("sub1")).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/Silo/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("authorization", basic_authorization("missing"))
                    .body(Body::from("grant_type=client_credentials"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn issues_verifiable_tokens_for_implicitly_selected_sub() {
        let app = test_app(Some("sub2")).await;
        let authorize = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/Silo/oauth2/authorize?response_type=code&client_id=relying-party&redirect_uri=http://localhost:8080/oauth&nonce=test-nonce&state=test-state&scope=custom_scope&scope=profile&claims=%7B%22id_token%22%3A%7B%22ignored%22%3Anull%7D%7D")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(authorize.status(), StatusCode::FOUND);
        let location = authorize
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        let url = url::Url::parse(location).unwrap();
        let code = url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, value)| value.into_owned())
            .unwrap();

        let token = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/Silo/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth&client_id=relying-party&client_secret=client_secret&code={code}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(token.status(), StatusCode::OK);
        let body = to_bytes(token.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id_token = json["id_token"].as_str().unwrap();

        let header = decode_header(id_token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some(crate::config::key_id()));

        let jwks = app
            .oneshot(
                Request::builder()
                    .uri("/Silo/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let jwks_body = to_bytes(jwks.into_body(), usize::MAX).await.unwrap();
        let jwks_json: serde_json::Value = serde_json::from_slice(&jwks_body).unwrap();
        let key = &jwks_json["keys"][0];
        let decoding_key = DecodingKey::from_rsa_components(
            key["n"].as_str().unwrap(),
            key["e"].as_str().unwrap(),
        )
        .unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["relying-party"]);
        validation.set_issuer(&["http://localhost:9393/Silo"]);

        let claims = decode::<serde_json::Value>(id_token, &decoding_key, &validation).unwrap();
        assert_eq!(claims.claims["nonce"], "test-nonce");
        assert_eq!(claims.claims["sub"], "sub2");
        assert_eq!(claims.claims["groups"][0], "auditor");
        assert_eq!(claims.claims["email"], "admin@example.com");
    }

    fn basic_authorization(client_id: &str) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{client_id}:client_secret").as_bytes())
        )
    }
}
