/// ! For more info, check https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
///
use crate::{
    adapter::Adapter,
    config::GLOBAL_CONFIG,
    token::{AuthToken, Token},
};
use reqwest::{header::ACCEPT, Client};
use serde::Deserialize;
use anyhow::anyhow;

/// Used to interact with the github api
#[derive(Clone, Debug)]
pub struct Github {
    pub cred: GithubCred,
}

// TODO: make a derive macro?
impl Adapter for Github {}

impl Github {
    /// Reconstruct the redirected url with the appended state (challenge)
    pub fn reconstruct_request_url(state: &str) -> anyhow::Result<url::Url> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        let gh_config = cfg.adapter.github.clone();
        let base_url = gh_config.gh_url;
        let client_id = gh_config.client_id;
        
        // get the redirect URI or return an error if not configured
        let redirect_uri = gh_config.redirect_url
            .ok_or_else(|| anyhow::anyhow!("GitHub redirect URL not configured"))?;

        // build the URL with the required parameters
        url::Url::parse_with_params(
            base_url.as_str(),
            &[
                ("client_id", client_id.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("state", state), // this corresponds to a registration request (challenge)
                                  // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
            ],
        ).map_err(|e| anyhow::anyhow!("Failed to construct URL: {}", e))
    }

    /// Validates that the state parameter is a valid token
    pub async fn validate_state(state: &str) -> anyhow::Result<()> {
        // TODO: check against stored state tokens
        if state.is_empty() {
            return Err(anyhow!("Invalid state parameter"));
        }
        Ok(())
    }

    /// Generate a url that uses should open to authenticate their github account
    ///
    /// This constructs a unique url per call, where each differs by the `state` parameter
    pub async fn request_url() -> Option<String> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        let gh_config = cfg.adapter.github.clone();
        let base_url = gh_config.gh_url;
        let client_id = gh_config.client_id;
        let redirect_uri = gh_config
            .redirect_url
            // FIXME
            .unwrap_or(url::Url::parse("https://rotko.net/").unwrap());

        let url = url::Url::parse_with_params(
            base_url.as_str(),
            &[
                ("client_id", client_id.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("state", &Token::generate().await.show()),
                // `state` is a number corresponds to a registration request
                // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
            ],
        )
        .unwrap();
        Some(url.to_string())
    }

    /// Gets github credentials to creates a [Github] instance
    pub async fn new(params: &GithubRedirectStepTwoParams) -> anyhow::Result<Self> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        let gh_config = cfg.adapter.github.clone();

        let client = Client::new();

        let uri = url::Url::parse_with_params(
            "https://github.com/login/oauth/access_token",
            &[
                ("client_id", gh_config.client_id.as_str()),
                ("client_secret", gh_config.client_secret.as_str()),
                ("code", params.code.as_str()),
                // TODO: check if this is needed?
                // ("redirect_uri", String::from("https://app.w3reg.org/").as_str()),
            ],
        )?;

        let response = client
            .get(uri)
            .header(ACCEPT, "application/json")
            .body("")
            .send()
            .await?;

        let credentials = response.json::<GithubCred>().await?;

        Ok(Self { cred: credentials })
    }

    /// Request username using provided credentials
    pub async fn request_username(&self) -> anyhow::Result<String> {
        let client = Client::new();
        let uri = url::Url::parse("https://api.github.com/user")?;
        let user = client
            .get(uri)
            .header("User-Agent", "W3R")
            .bearer_auth(self.cred.access_token.as_str())
            .send()
            .await?;

        let obj = serde_json::from_str::<serde_json::Value>(&user.text().await.unwrap_or_default())
            .unwrap_or_default();

        return Ok(obj["login"]
            .as_str()
            .unwrap_or_default()
            .trim_matches('"')
            .to_string());
    }
}

/// Those params are added to the redirected url by github in step 2, check this for more
///
/// https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#2-users-are-redirected-back-to-your-site-by-github
#[derive(Debug, Deserialize, Clone)]
pub struct GithubRedirectStepTwoParams {
    pub code: String,
    pub state: String,
}

/// Possible url params to an access token request, check this for more
///
/// https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#2-users-are-redirected-back-to-your-site-by-github
#[allow(unused)]
#[derive(Debug, Deserialize, Clone)]
pub struct GithubATRequestParams {
    pub client_id: String,
    pub client_secret: String,
    pub code: String,
    pub redirect_uri: Option<String>,
}

#[allow(unused)]
#[derive(Debug, Deserialize, Clone)]
pub struct GithubCred {
    pub access_token: String,
    pub scope: String,
    pub token_type: String,
}
