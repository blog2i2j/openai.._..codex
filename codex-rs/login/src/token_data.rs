use base64::Engine;
use chrono::DateTime;
use chrono::Utc;
use codex_protocol::auth::PlanType;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use thiserror::Error;

const CHATGPT_ACCOUNT_ROUTING_COOKIE_ALLOWLIST: &[&str] = &["_account_is_fedramp"];

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Default)]
pub struct TokenData {
    /// Flat info parsed from the JWT in auth.json.
    #[serde(
        deserialize_with = "deserialize_id_token",
        serialize_with = "serialize_id_token"
    )]
    pub id_token: IdTokenInfo,

    /// This is a JWT.
    pub access_token: String,

    pub refresh_token: String,

    pub account_id: Option<String>,
}

/// Flat subset of useful claims in id_token from auth.json.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IdTokenInfo {
    pub email: Option<String>,
    /// The ChatGPT subscription plan type
    /// (e.g., "free", "plus", "pro", "business", "enterprise", "edu").
    /// (Note: values may vary by backend.)
    pub chatgpt_plan_type: Option<PlanType>,
    /// ChatGPT user identifier associated with the token, if present.
    pub chatgpt_user_id: Option<String>,
    /// Organization/workspace identifier associated with the token, if present.
    pub chatgpt_account_id: Option<String>,
    /// AuthAPI-minted cookies that route ChatGPT backend-api requests for the selected workspace.
    pub chatgpt_account_routing_cookies: BTreeMap<String, String>,
    pub raw_jwt: String,
}

impl IdTokenInfo {
    pub fn get_chatgpt_plan_type(&self) -> Option<String> {
        self.chatgpt_plan_type.as_ref().map(|t| match t {
            PlanType::Known(plan) => plan.display_name().to_string(),
            PlanType::Unknown(s) => s.clone(),
        })
    }

    pub fn get_chatgpt_plan_type_raw(&self) -> Option<String> {
        self.chatgpt_plan_type.as_ref().map(|t| match t {
            PlanType::Known(plan) => plan.raw_value().to_string(),
            PlanType::Unknown(s) => s.clone(),
        })
    }

    pub fn is_workspace_account(&self) -> bool {
        matches!(
            self.chatgpt_plan_type,
            Some(PlanType::Known(plan)) if plan.is_workspace_account()
        )
    }

    pub fn chatgpt_account_routing_cookies(&self) -> Vec<(String, String)> {
        self.chatgpt_account_routing_cookies
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }
}

#[derive(Deserialize)]
struct IdClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(rename = "https://api.openai.com/profile", default)]
    profile: Option<ProfileClaims>,
    #[serde(rename = "https://api.openai.com/auth", default)]
    auth: Option<AuthClaims>,
}

#[derive(Deserialize)]
struct ProfileClaims {
    #[serde(default)]
    email: Option<String>,
}

#[derive(Deserialize)]
struct AuthClaims {
    #[serde(default)]
    chatgpt_plan_type: Option<PlanType>,
    #[serde(default)]
    chatgpt_user_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    chatgpt_account_id: Option<String>,
    #[serde(default)]
    chatgpt_account_routing_cookies: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct StandardJwtClaims {
    #[serde(default)]
    exp: Option<i64>,
}

#[derive(Debug, Error)]
pub enum IdTokenInfoError {
    #[error("invalid ID token format")]
    InvalidFormat,
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn decode_jwt_payload<T: DeserializeOwned>(jwt: &str) -> Result<T, IdTokenInfoError> {
    // JWT format: header.payload.signature
    let mut parts = jwt.split('.');
    let (_header_b64, payload_b64, _sig_b64) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) if !h.is_empty() && !p.is_empty() && !s.is_empty() => (h, p, s),
        _ => return Err(IdTokenInfoError::InvalidFormat),
    };

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64)?;
    let claims = serde_json::from_slice(&payload_bytes)?;
    Ok(claims)
}

pub fn parse_jwt_expiration(jwt: &str) -> Result<Option<DateTime<Utc>>, IdTokenInfoError> {
    let claims: StandardJwtClaims = decode_jwt_payload(jwt)?;
    Ok(claims
        .exp
        .and_then(|exp| DateTime::<Utc>::from_timestamp(exp, 0)))
}

pub fn parse_chatgpt_jwt_claims(jwt: &str) -> Result<IdTokenInfo, IdTokenInfoError> {
    let claims: IdClaims = decode_jwt_payload(jwt)?;
    let email = claims
        .email
        .or_else(|| claims.profile.and_then(|profile| profile.email));

    match claims.auth {
        Some(auth) => {
            let chatgpt_account_routing_cookies =
                filter_chatgpt_account_routing_cookies(auth.chatgpt_account_routing_cookies);
            Ok(IdTokenInfo {
                email,
                raw_jwt: jwt.to_string(),
                chatgpt_plan_type: auth.chatgpt_plan_type,
                chatgpt_user_id: auth.chatgpt_user_id.or(auth.user_id),
                chatgpt_account_id: auth.chatgpt_account_id,
                chatgpt_account_routing_cookies,
            })
        }
        None => Ok(IdTokenInfo {
            email,
            raw_jwt: jwt.to_string(),
            chatgpt_plan_type: None,
            chatgpt_user_id: None,
            chatgpt_account_id: None,
            chatgpt_account_routing_cookies: BTreeMap::new(),
        }),
    }
}

fn filter_chatgpt_account_routing_cookies(
    routing_cookies: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    routing_cookies
        .into_iter()
        .filter(|(name, value)| is_allowed_chatgpt_account_routing_cookie(name, value))
        .collect()
}

fn is_allowed_chatgpt_account_routing_cookie(name: &str, value: &str) -> bool {
    CHATGPT_ACCOUNT_ROUTING_COOKIE_ALLOWLIST.contains(&name)
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| !matches!(byte, 0..=31 | 127 | b';' | b','))
}

fn deserialize_id_token<'de, D>(deserializer: D) -> Result<IdTokenInfo, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_chatgpt_jwt_claims(&s).map_err(serde::de::Error::custom)
}

fn serialize_id_token<S>(id_token: &IdTokenInfo, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&id_token.raw_jwt)
}

#[cfg(test)]
#[path = "token_data_tests.rs"]
mod tests;
