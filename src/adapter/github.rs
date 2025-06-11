/// ! For more info, check https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
///
use crate::{
    adapter::Adapter,
    api::RedisConnection,
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

    /// Validates that the state parameter is a valid, stored, single-use token
    ///
    /// Validates the state parameter is:
    /// - Cryptographically secure (8 characters from base-20 alphabet)
    /// - Previously stored in Redis with expiration
    /// - Single-use (removed after validation)
    pub async fn validate_state(state: &str) -> anyhow::Result<()> {
        if state.len() != 8 {
            return Err(anyhow!("Invalid state parameter length"));
        }
        
        let mut redis_conn = RedisConnection::default().await?;
        let key = format!("oauth_state:{}", state);
        
        // Check if state exists in Redis
        let exists: bool = redis_conn.conn.exists(&key).await
            .map_err(|e| anyhow!("Failed to check state in Redis: {}", e))?;
        
        if !exists {
            return Err(anyhow!("Invalid or expired state parameter"));
        }
        
        // Remove state to prevent replay attacks (single-use)
        let _: () = redis_conn.conn.del(&key).await
            .map_err(|e| anyhow!("Failed to remove state from Redis: {}", e))?;
        
        Ok(())
    }

    /// Generate a url that users should open to authenticate their github account
    ///
    /// This constructs a unique url per call, where each differs by the `state` parameter.
    /// The state is stored in Redis with 10-minute expiration for security validation.
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

        // Generate cryptographically secure state token
        let state_token = Token::generate().await.show();
        
        // Store state in Redis with 10-minute expiration
        if let Ok(mut redis_conn) = RedisConnection::default().await {
            let key = format!("oauth_state:{}", state_token);
            let _: Result<(), _> = redis_conn.conn.set_ex(&key, "valid", 600).await;
        }

        let url = url::Url::parse_with_params(
            base_url.as_str(),
            &[
                ("client_id", client_id.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("state", &state_token),
                // `state` corresponds to a registration request
                // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
            ],
        )
        .unwrap();
        Some(url.to_string())
    }

    /// Gets github credentials to creates a [Github] instance
    ///
    /// # Errors
    ///
    /// - `params.state` is invalid, expired, or already used (replay attack protection)
    /// - Failed to send http request to the Github API.
    /// - Fails to deserialize Github http response to [GithubCred]
    pub async fn new(params: &GithubRedirectStepTwoParams) -> anyhow::Result<Self> {
        // Validate state parameter against stored tokens
        Github::validate_state(&params.state).await?;

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

        Ok(obj["login"]
            .as_str()
            .unwrap_or_default()
            .trim_matches('"')
            .to_string())
    }
}

/// Those params are added to the redirected url by github in step 2, check this for more
///
/// [Resource](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#2-users-are-redirected-back-to-your-site-by-github)
#[derive(Debug, Deserialize, Clone)]
pub struct GithubRedirectStepTwoParams {
    /// Temporarily Constructed by Github to finish step 2 in OAuth
    pub code: String,
    /// Constructed by w3r to uniquely identify a Github OAuth request
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
