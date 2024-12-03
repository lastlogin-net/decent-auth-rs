use std::collections::{HashMap,BTreeMap};
use crate::{
    get_return_target,DaHttpResponse,OAUTH_STATE_PREFIX,KvStore,
    DaHttpRequest,kv,error,SESSION_PREFIX,Session,Config,DaError
};
use openidconnect::{
    Scope,PkceCodeChallenge,Nonce,CsrfToken,TokenResponse,PkceCodeVerifier,
    AuthorizationCode,RedirectUrl,IssuerUrl,ClientId,
    core::{CoreAuthenticationFlow,CoreClient,CoreProviderMetadata},
};
use serde::{Serialize,Deserialize};
use url::Url;
use cookie::{Cookie};

#[cfg(target_arch = "wasm32")]
use crate::http_client;
#[cfg(not(target_arch = "wasm32"))]
use openidconnect::reqwest::http_client;

#[derive(Debug,Serialize,Deserialize)]
pub struct FlowState {
    pub pkce_verifier: String,
    pub nonce: String,
    pub return_target: String,
    pub provider_uri: String,
}

pub fn handle_login<T: kv::Store>(req: &DaHttpRequest, kv_store: &mut KvStore<T>, storage_prefix: &str, path_prefix: &str, provider_uri: &str) -> error::Result<DaHttpResponse> {

    let parsed_url = Url::parse(&req.url)?; 

    let client = get_client(provider_uri, &path_prefix, &parsed_url)?;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let flow_state = FlowState{
        pkce_verifier: pkce_verifier.secret().to_string(),
        nonce: nonce.secret().to_string(),
        return_target: get_return_target(&req),
        provider_uri: provider_uri.to_string(),
    };

    let state_key = format!("/{}/{}/{}", storage_prefix, OAUTH_STATE_PREFIX, csrf_token.secret());
    kv_store.set(&state_key, flow_state)?;

    let mut res = DaHttpResponse::new(303, "Hi there");

    res.headers = BTreeMap::from([
        ("Location".to_string(), vec![format!("{}", auth_url)]),
    ]);

    Ok(res)
}

pub fn handle_callback<T: kv::Store>(req: &DaHttpRequest, kv_store: &mut KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> {

    let parsed_url = Url::parse(&req.url)?; 

    let hash_query: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();

    let state = hash_query["state"].clone();

    let state_key = format!("/{}/{}/{}", config.storage_prefix, OAUTH_STATE_PREFIX, state);
    let flow_state: FlowState = kv_store.get(&state_key)?;

    let code = hash_query["code"].clone();

    let client = get_client(&flow_state.provider_uri, &config.path_prefix, &parsed_url)?;

    let token_response =
        client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(flow_state.pkce_verifier))
            .request(http_client)?;

    let id_token = token_response.id_token().ok_or(DaError::new("Missing id_token"))?;

    let nonce = Nonce::new(flow_state.nonce);
    let claims = id_token.claims(&client.id_token_verifier(), &nonce)?;

    let session_key = CsrfToken::new_random().secret().to_string();
    let session_cookie = Cookie::build((format!("{}_session_key", config.storage_prefix), &session_key))
        .path("/")
        .secure(true)
        .http_only(true);

    let session = Session{
        id_type: "email".to_string(),
        id: claims.subject().to_string(),
    };

    let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);
    kv_store.set(&kv_session_key, &session)?;

    let mut res = DaHttpResponse::new(303, "");

    res.headers = BTreeMap::from([
        ("Location".to_string(), vec![flow_state.return_target]),
        ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
    ]);

    Ok(res)
}

fn get_client(provider_url: &str, path_prefix: &str, parsed_url: &Url) -> error::Result<CoreClient> {
    let provider_metadata = CoreProviderMetadata::discover(
        &IssuerUrl::new(provider_url.to_string())?,
        http_client,
    ).expect("meta failed");

    let host = parsed_url.host().ok_or(DaError::new("Missing host"))?;

    let uri = format!("https://{host}{path_prefix}/callback");
    let client =
        CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(format!("https://{host}")),
            None,
        )
        .set_redirect_uri(RedirectUrl::new(uri)?);

    Ok(client)
}
