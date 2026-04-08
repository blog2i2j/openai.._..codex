use codex_client::Request;
use http::HeaderMap;
use http::HeaderValue;

/// Provides bearer and account identity information for API requests.
///
/// Implementations should be cheap and non-blocking; any asynchronous
/// refresh or I/O should be handled by higher layers before requests
/// reach this interface.
pub trait AuthProvider: Send + Sync {
    fn bearer_token(&self) -> Option<String>;
    fn account_id(&self) -> Option<String> {
        None
    }
    fn chatgpt_account_routing_cookies(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}

pub(crate) fn add_auth_headers_to_header_map<A: AuthProvider>(auth: &A, headers: &mut HeaderMap) {
    if let Some(token) = auth.bearer_token()
        && let Ok(header) = HeaderValue::from_str(&format!("Bearer {token}"))
    {
        let _ = headers.insert(http::header::AUTHORIZATION, header);
    }
    if let Some(account_id) = auth.account_id()
        && let Ok(header) = HeaderValue::from_str(&account_id)
    {
        let _ = headers.insert("ChatGPT-Account-ID", header);
    }
    for (name, value) in auth.chatgpt_account_routing_cookies() {
        add_chatgpt_account_routing_cookie(headers, &name, &value);
    }
}

fn add_chatgpt_account_routing_cookie(headers: &mut HeaderMap, name: &str, value: &str) {
    let cookie_pair = format!("{name}={value}");
    let Ok(cookie_header_value) = HeaderValue::from_str(&cookie_pair) else {
        return;
    };

    let Some(value) = headers.get(http::header::COOKIE) else {
        headers.insert(http::header::COOKIE, cookie_header_value);
        return;
    };

    let Ok(existing) = value.to_str() else {
        return;
    };
    if existing
        .split(';')
        .any(|cookie| cookie.trim() == cookie_pair)
    {
        return;
    }

    if let Ok(value) = HeaderValue::from_str(&format!("{existing}; {cookie_pair}")) {
        headers.insert(http::header::COOKIE, value);
    }
}

pub(crate) fn add_auth_headers<A: AuthProvider>(auth: &A, mut req: Request) -> Request {
    add_auth_headers_to_header_map(auth, &mut req.headers);
    req
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAuth {
        chatgpt_account_routing_cookies: Vec<(String, String)>,
    }

    impl AuthProvider for TestAuth {
        fn bearer_token(&self) -> Option<String> {
            None
        }

        fn chatgpt_account_routing_cookies(&self) -> Vec<(String, String)> {
            self.chatgpt_account_routing_cookies.clone()
        }
    }

    #[test]
    fn auth_headers_add_account_routing_cookie() {
        let auth = TestAuth {
            chatgpt_account_routing_cookies: vec![(
                "_account_is_fedramp".to_string(),
                "true".to_string(),
            )],
        };
        let mut headers = HeaderMap::new();

        add_auth_headers_to_header_map(&auth, &mut headers);

        assert_eq!(
            headers
                .get(http::header::COOKIE)
                .and_then(|v| v.to_str().ok()),
            Some("_account_is_fedramp=true")
        );
    }

    #[test]
    fn auth_headers_do_not_add_account_routing_cookie_by_default() {
        let auth = TestAuth {
            chatgpt_account_routing_cookies: Vec::new(),
        };
        let mut headers = HeaderMap::new();

        add_auth_headers_to_header_map(&auth, &mut headers);

        assert!(headers.get(http::header::COOKIE).is_none());
    }

    #[test]
    fn auth_headers_merge_account_routing_cookie_with_existing_cookie() {
        let auth = TestAuth {
            chatgpt_account_routing_cookies: vec![(
                "_account_is_fedramp".to_string(),
                "true".to_string(),
            )],
        };
        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, HeaderValue::from_static("foo=bar"));

        add_auth_headers_to_header_map(&auth, &mut headers);

        assert_eq!(
            headers
                .get(http::header::COOKIE)
                .and_then(|v| v.to_str().ok()),
            Some("foo=bar; _account_is_fedramp=true")
        );
    }
}
