use crate::{
    KvStore,get_session,DaError,Session,handle,DaHttpRequest,DaHttpResponse,
    Config,error,kv,BTreeMap,HeaderValue,HeaderName
};
use openidconnect::{
    HttpRequest,HttpResponse,http::{HeaderMap,StatusCode},
};
use extism_pdk::{plugin_fn,host_fn,FnResult,Json,http as extism_http};
use std::str::FromStr;

const ERROR_CODE_NO_ERROR: u8 = 0;

#[host_fn]
extern "ExtismHost" {
    fn kv_read(key: &str) -> Vec<u8>; 
    fn kv_write(key: &str, value: Vec<u8>); 
    fn kv_delete(key: &str); 
    fn kv_list(prefix: &str) -> Vec<u8>; 
}

impl From<extism_pdk::Error> for kv::Error {
    fn from(_value: extism_pdk::Error) -> Self {
        Self::new("extism_pdk::Error")
    }
}

impl From<extism_pdk::Error> for DaError {
    fn from(_value: extism_pdk::Error) -> Self {
        Self::new("extism_pdk::Error")
    }
}

struct ExtismKv {
}

impl kv::Store for ExtismKv {
    fn get(&self, key: &str) -> Result<Vec<u8>, kv::Error> {
        let bytes = unsafe { kv_read(key)? };
        if bytes[0] != ERROR_CODE_NO_ERROR {
            return Err(kv::Error::new("kv_read bad code"));
        }
        // TODO: I think this to_vec results in an extra copy. Can we avoid it?
        Ok((&bytes[1..]).to_vec())
    }
    
    fn set(&self, key: &str, value: Vec<u8>) -> Result<(), kv::Error> {
        unsafe { kv_write(key, value)? };
        Ok(())
    }

    fn list(&self, key: &str) -> Result<Vec<String>, kv::Error> {
        let bytes = unsafe { kv_list(key)? };
        if bytes[0] != ERROR_CODE_NO_ERROR {
            return Err(kv::Error::new("kv_list bad code"));
        }

        Ok(serde_json::from_slice::<Vec<String>>(&bytes[1..])?)
    }

    fn delete(&self, key: &str) -> Result<(), kv::Error> {
        unsafe { kv_delete(key)? };
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
pub fn http_client(req: HttpRequest) -> std::result::Result<HttpResponse, DaError> {

    let mut ereq = extism_pdk::HttpRequest{
        url: req.url.to_string(),
        method: Some(req.method.to_string()),
        headers: BTreeMap::new(),
    };

    for (key, value) in req.headers.iter() {
        ereq.headers.insert(key.to_string(), value.to_str()?.to_string());
    }

    let eres = extism_http::request::<Vec<u8>>(&ereq, Some(req.body))?;

    let mut headers = HeaderMap::new();

    for (k, v) in eres.headers() {
        headers.insert(HeaderName::from_str(k)?, HeaderValue::from_str(v)?);
    }

    let res = HttpResponse{
        status_code: StatusCode::from_u16(eres.status_code())?,
        headers,
        body: eres.body(),
    };

    Ok(res)
}

fn get_config() -> error::Result<Config> {
    let config_json = extism_pdk::config::get("config")?.ok_or(DaError::new("Missing config"))?;
    let config = serde_json::from_str(&config_json)?;
    Ok(config)
}


#[plugin_fn]
pub extern "C" fn extism_handle(Json(req): Json<DaHttpRequest>) -> FnResult<Json<DaHttpResponse>> {

    let config = get_config().map_err(|_| DaError::new("Failed to get config for handler"))?;

    let kv_store = KvStore{
        byte_kv: ExtismKv{},
    };

    let result = handle(req, &kv_store, &config);

    if let Ok(res) = result {
        Ok(Json(res))
    }
    else {
        Err(extism_pdk::Error::msg("call to handle failed").into())
    }
}

#[plugin_fn]
pub extern "C" fn extism_get_session(Json(req): Json<DaHttpRequest>) -> FnResult<Json<Option<Session>>> {
    let config = get_config().map_err(|_| DaError::new("Failed to get config for session"))?;

    let kv_store = KvStore{
        byte_kv: ExtismKv{},
    };

    let session = get_session(&req, &kv_store, &config);

    Ok(Json(session))
}
