use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub scopes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
}

#[derive(Debug)]
pub struct AuthorizationQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub nonce: Option<String>,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub login_hint: Option<String>,
    pub mock_user: Option<String>,
}

impl AuthorizationQuery {
    pub fn parse(raw_query: Option<&str>) -> Self {
        let raw_query = raw_query.unwrap_or_default();
        let mut response_type = None;
        let mut client_id = None;
        let mut redirect_uri = None;
        let mut nonce = None;
        let mut state = None;
        let mut scope_values = Vec::new();
        let mut login_hint = None;
        let mut mock_user = None;

        for (key, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
            match key.as_ref() {
                "response_type" => response_type = Some(value.into_owned()),
                "client_id" => client_id = Some(value.into_owned()),
                "redirect_uri" => redirect_uri = Some(value.into_owned()),
                "nonce" => nonce = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "scope" => scope_values.push(value.into_owned()),
                "login_hint" => login_hint = Some(value.into_owned()),
                "mock_user" => mock_user = Some(value.into_owned()),
                _ => {}
            }
        }

        Self {
            response_type,
            client_id,
            redirect_uri,
            nonce,
            state,
            scope: normalize_scopes(scope_values),
            login_hint,
            mock_user,
        }
    }
}

pub fn normalize_scopes<I, S>(values: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut scopes = Vec::new();
    for value in values {
        for scope in value.as_ref().split_ascii_whitespace() {
            if !scopes.iter().any(|existing| existing == scope) {
                scopes.push(scope.to_string());
            }
        }
    }
    (!scopes.is_empty()).then(|| scopes.join(" "))
}

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub scope: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub id_token: String,
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{normalize_scopes, AuthorizationQuery, TokenResponse};

    #[test]
    fn combines_and_deduplicates_requested_scopes() {
        let query = AuthorizationQuery::parse(Some(
            "scope=openid%20profile&scope=custom%20profile&client_id=client",
        ));

        assert_eq!(query.scope.as_deref(), Some("openid profile custom"));
    }

    #[test]
    fn omits_scope_when_none_was_requested() {
        let query = AuthorizationQuery::parse(Some("client_id=client"));

        assert_eq!(query.scope, None);

        let response = TokenResponse {
            id_token: "id-token".to_string(),
            access_token: "access-token".to_string(),
            scope: None,
        };
        let json = serde_json::to_value(response).unwrap();
        assert!(json.get("scope").is_none());
        assert!(json.get("refresh_token").is_none());
    }

    #[test]
    fn normalizes_scope_values_in_first_seen_order() {
        assert_eq!(
            normalize_scopes(["read write", "read admin"]),
            Some("read write admin".to_string())
        );
        assert_eq!(normalize_scopes(["  "]), None);
    }
}
