use crate::{
    handle,DaHttpRequest,BTreeMap,get_session,Session,KvStore,
    Config,kv,
};

pub struct Server<T: kv::Store> {
    pub config: Config,
    kv_store: KvStore<T>,
}

impl<T: kv::Store> Server<T> {
    pub fn new(config: Config, kv_store: T) -> Self {
        Self{
            config,
            kv_store: KvStore{
                byte_kv: kv_store,
            },
        }
    }

    pub fn get_session(&self, in_headers: &http::HeaderMap) -> Option<Session> {

        let mut headers = BTreeMap::new();
        for (key, value) in in_headers {
            if let Ok(val) = value.to_str() {
                headers.insert(key.to_string(), vec![val.to_string()]);
            }
        }

        let req = DaHttpRequest{
            url: "".to_string(),
            method: Some("GET".to_string()),
            headers,
            body: "".to_string(),
        };

        get_session(&req, &self.kv_store, &self.config)
    }

    pub fn handle(&self, req: http::Request<bytes::Bytes>) -> http::Response<bytes::Bytes> {

        let mut host = None;
        let mut headers = BTreeMap::new();
        for (key, value) in req.headers() {
            if let Ok(val) = value.to_str() {
                if key == "host" {
                    host = Some(val);
                }
                headers.insert(key.to_string(), vec![val.to_string()]);
            }
        }

        let url = if let Some(query) = req.uri().query() {
            format!("http://{}{}?{}", host.unwrap_or_default(), req.uri().path(), query)
        }
        else {
            format!("http://{}{}", host.unwrap_or_default(), req.uri().path())
        };

        let body = match std::str::from_utf8(req.body()) {
            Ok(body) => body,
            Err(e) => {
                let mut res = http::Response::new(bytes::Bytes::from(e.to_string()));
                *res.status_mut() = http::StatusCode::BAD_REQUEST;
                return res;
            },
        };

        let da_req = DaHttpRequest{
            url,
            method: Some(req.method().as_str().to_string()),
            headers,
            body: body.to_string(),
        };

        let da_res = match handle(da_req, &self.kv_store, &self.config) {
            Ok(da_res) => da_res,
            Err(e) => {
                let mut res = http::Response::new(bytes::Bytes::from(e.to_string()));
                *res.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                return res;
            },
        };

        let status_code = match http::StatusCode::from_u16(da_res.code) {
            Ok(code) => code,
            Err(e) => {
                let mut res = http::Response::new(bytes::Bytes::from(e.to_string()));
                *res.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                return res;
            },
        };

        let mut res_builder = http::Response::builder()
            .status(status_code);

        for (key, values) in da_res.headers {
            res_builder = res_builder.header(key, values[0].clone());
        }

        let res = match res_builder.body(bytes::Bytes::from(da_res.body)) {
            Ok(res) => res,
            Err(e) => {
                let mut res = http::Response::new(bytes::Bytes::from(e.to_string()));
                *res.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                return res;
            },
        };

        res
    }
}
