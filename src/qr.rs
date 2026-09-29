use crate::{
    DaHttpRequest,DaHttpResponse,error,kv,KvStore,Config, get_return_target,get_session,
    Session,SessionBuilder,generate_random_text,parse_params,
    create_session_cookie,SESSION_PREFIX,template,Templater,get_host,
};
use url::Url;
use std::collections::{HashMap,BTreeMap};
use qrcode::{QrCode};
use qrcode::render::svg;
use serde::{Serialize,Deserialize};


#[derive(Debug,Serialize,Deserialize)]
struct PendingQrData {
    return_target: String,
    session: Option<Session>,
}

fn method_not_allowed(allowed: &str) -> DaHttpResponse {
    let mut res = DaHttpResponse::new(405, "Method not allowed");
    res.headers = BTreeMap::from([
        ("Allow".to_string(), vec![allowed.to_string()]),
    ]);
    return res;
}

fn has_method(req: &DaHttpRequest, method: &str) -> bool {
    req.method.as_deref()
        .map(|m| m.eq_ignore_ascii_case(method))
        .unwrap_or(false)
}

pub fn handle_login<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config, templater: &Templater) -> error::Result<DaHttpResponse> 
    where T: kv::Store,
{
    // TODO: this key is being reused for multiple purposes on multiple devices. We should have 2
    // separate keys, and the one used to retrieve the final session should never exist anywhere
    // other than the device that is logging in.
    let qr_key = generate_random_text();

    let host = get_host(req, config)?;

    let qr_url = format!("https://{}{}/qr?key={}", host, config.path_prefix, qr_key);

    let code = QrCode::new(&qr_url);
    let qr_svg = code?.render()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();

    let data = template::QrData{
        config,
        return_target: get_return_target(&req),
        qr_svg,
        qr_key: qr_key.clone(),
        qr_url: qr_url,
    };
    let body = templater.render_qr_code_page(&data)?;


    let storage_key = format!("/{}/pending_qr_logins/{}", config.storage_prefix, qr_key);

    let state = PendingQrData{
        return_target: get_return_target(req),
        session: None,
    };

    kv_store.set(&storage_key, state)?;

    let mut res = DaHttpResponse::new(200, &body);
    res.headers = BTreeMap::from([
        ("Content-Type".to_string(), vec!["text/html".to_string()]),
    ]);

    Ok(res)
}


pub fn handle<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config, templater: &Templater) -> error::Result<DaHttpResponse> {

    let parsed_url = Url::parse(&req.url)?; 
    let path = parsed_url.path();

    if path == &format!("{}/qr", config.path_prefix) {

        if !has_method(req, "GET") {
            return Ok(method_not_allowed("GET"));
        }

        let params = parse_params(&req).unwrap_or(HashMap::new());

        let qr_key = if let Some(key) = params.get("key") {
            key
        }
        else {
            return Ok(DaHttpResponse::new(400, &format!("Missing key param")));
        };

        let session = get_session(&req, &kv_store, config);
        if session.is_none() {
            let mut res = DaHttpResponse::new(303, "");
            let ret = &format!("{}?key={}", path, qr_key);
            let ret = urlencoding::encode(ret);
            let uri = format!("{}?return_target={}", config.path_prefix, ret);
            res.headers = BTreeMap::from([
                ("Location".to_string(), vec![uri]),
            ]);
            return Ok(res);
        }

        // TODO: is this duplication with the code above necessary?
        let qr_key = if let Some(key) = params.get("key") {
            key
        }
        else {
            return Ok(DaHttpResponse::new(400, &format!("Missing key param")));
        };

        let data = template::QrLinkData {
            config,
            return_target: get_return_target(&req),
            qr_key: qr_key.to_string(),
        };
        let body = templater.render_qr_code_link_page(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        return Ok(res);
    }
    else if path == &format!("{}/qr/approve", config.path_prefix) {

        if !has_method(req, "POST") {
            return Ok(method_not_allowed("POST"));
        }

        let params = parse_params(&req).unwrap_or(HashMap::new());

        let qr_key = if let Some(key) = params.get("key") {
            key
        }
        else {
            return Ok(DaHttpResponse::new(400, &format!("Missing key param")));
        };

        let storage_key = format!("/{}/pending_qr_logins/{}", config.storage_prefix, qr_key);

        let mut state: PendingQrData = kv_store.get(&storage_key)?;

        let session = get_session(&req, &kv_store, config).unwrap();

        state.session = Some(session); 

        kv_store.set(&storage_key, state)?;

        let data = template::CommonData{
            config,
            return_target: get_return_target(&req),
        };
        let body = templater.render_qr_approved_page(&data)?;


        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        return Ok(res);
    }
    else if path == &format!("{}/qr/finalize", config.path_prefix) {

        if !has_method(req, "POST") {
            return Ok(method_not_allowed("POST"));
        }

        let params = parse_params(&req).unwrap_or(HashMap::new());

        let qr_key = if let Some(key) = params.get("key") {
            key
        }
        else {
            return Ok(DaHttpResponse::new(400, &format!("Missing key param")));
        };

        let storage_key = format!("/{}/pending_qr_logins/{}", config.storage_prefix, qr_key);

        let state: PendingQrData = kv_store.get(&storage_key)?;

        let session = if let Some(session) = state.session {
            session
        }
        else {
            return Ok(DaHttpResponse::new(400, &format!("No session")));
        };

        let session_key = generate_random_text();
        let session_cookie = create_session_cookie(&config.storage_prefix, &session_key);

        let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);


        let new_session = SessionBuilder::new(session.id_type, &session.id)
            .build();
        kv_store.set(&kv_session_key, &new_session)?;

        // Consume the pending state so this QR key cannot mint another
        // session. The Store trait has no atomic take/get-and-delete, so this
        // only prevents sequential replay, not concurrent double-finalize.
        kv_store.delete(&storage_key)?;

        let mut res = DaHttpResponse::new(303, "");
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![state.return_target]),
            ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
        ]);

        return Ok(res);
    }

    let res = DaHttpResponse::new(200, "Hi there");
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::KvStore as MemoryKvStore;
    use std::sync::Arc;

    fn qr_config() -> Config {
        Config {
            storage_prefix: "test".to_string(),
            path_prefix: "/decent-auth".to_string(),
            behind_proxy: false,
            admin_id: None,
            id_header_name: None,
            login_methods: Some(vec![]),
            smtp_config: None,
            runtime: Some("test runtime".to_string()),
        }
    }

    fn da_request(
        method: Option<&str>,
        url: &str,
        body: &str,
        cookie: Option<&str>,
    ) -> DaHttpRequest {
        let mut headers =
            BTreeMap::from([("host".to_string(), vec!["localhost".to_string()])]);
        if let Some(cookie) = cookie {
            headers.insert("cookie".to_string(), vec![cookie.to_string()]);
        }
        DaHttpRequest {
            url: url.to_string(),
            headers,
            method: method.map(|m| m.to_string()),
            body: body.to_string(),
        }
    }

    fn session_count(byte_kv: &MemoryKvStore) -> usize {
        use crate::kv::Store as _;
        byte_kv.list("/test/sessions/").unwrap().len()
    }

    #[test]
    fn qr_endpoints_reject_missing_method() {
        let byte_kv = Arc::new(MemoryKvStore::default());
        let kv_store = KvStore { byte_kv };
        let templater = Templater::new();
        let config = qr_config();

        for (url, allow) in [
            ("http://localhost/decent-auth/qr?key=abc", "GET"),
            ("http://localhost/decent-auth/qr/approve?key=abc", "POST"),
            ("http://localhost/decent-auth/qr/finalize?key=abc", "POST"),
        ] {
            let req = da_request(None, url, "", None);
            let res = handle(&req, &kv_store, &config, &templater).unwrap();

            assert_eq!(res.code, 405, "missing method must be rejected for {url}");
            assert_eq!(res.headers.get("Allow"), Some(&vec![allow.to_string()]));
        }
    }

    #[test]
    fn qr_endpoints_reject_wrong_methods() {
        let byte_kv = Arc::new(MemoryKvStore::default());
        let kv_store = KvStore { byte_kv };
        let templater = Templater::new();
        let config = qr_config();

        for (method, url, allow) in [
            ("POST", "http://localhost/decent-auth/qr?key=abc", "GET"),
            ("PUT", "http://localhost/decent-auth/qr?key=abc", "GET"),
            ("GET", "http://localhost/decent-auth/qr/approve?key=abc", "POST"),
            ("GET", "http://localhost/decent-auth/qr/finalize?key=abc", "POST"),
            ("PUT", "http://localhost/decent-auth/qr/finalize?key=abc", "POST"),
        ] {
            let req = da_request(Some(method), url, "", None);
            let res = handle(&req, &kv_store, &config, &templater).unwrap();

            assert_eq!(res.code, 405, "{method} {url} must be rejected");
            assert_eq!(res.headers.get("Allow"), Some(&vec![allow.to_string()]));
        }
    }

    #[test]
    fn qr_approve_get_is_rejected_before_lookup_and_creates_nothing() {
        use crate::kv::Store as _;

        let byte_kv = Arc::new(MemoryKvStore::default());
        let kv_store = KvStore { byte_kv: byte_kv.clone() };
        let templater = Templater::new();
        let config = qr_config();

        // No pending state and no session cookie exist. Without the method
        // guard the handler would look up the key (erroring out) and unwrap a
        // missing session, so a clean 405 proves the guard runs first.
        let req = da_request(
            Some("GET"),
            "http://localhost/decent-auth/qr/approve?key=attackerkey",
            "",
            None,
        );

        let res = handle(&req, &kv_store, &config, &templater).unwrap();

        assert_eq!(res.code, 405);
        assert_eq!(res.headers.get("Allow"), Some(&vec!["POST".to_string()]));
        assert!(
            byte_kv.list("/").unwrap().is_empty(),
            "rejected request must not create pending state or sessions"
        );
    }

    #[test]
    fn qr_approve_get_does_not_modify_existing_pending_state() {
        let byte_kv = Arc::new(MemoryKvStore::default());
        let kv_store = KvStore { byte_kv: byte_kv.clone() };
        let templater = Templater::new();
        let config = qr_config();

        // A SameSite=Lax session cookie is sent on a top-level GET navigation,
        // so this is the exact shape of the approval CSRF request.
        let approver_session =
            SessionBuilder::new(crate::IdType::Email, "approver@example.com").build();
        kv_store
            .set("/test/sessions/approver", &approver_session)
            .unwrap();
        kv_store
            .set(
                "/test/pending_qr_logins/victimkey",
                PendingQrData {
                    return_target: "/".to_string(),
                    session: None,
                },
            )
            .unwrap();

        let req = da_request(
            Some("GET"),
            "http://localhost/decent-auth/qr/approve?key=victimkey",
            "",
            Some("test_session_key=approver"),
        );

        let res = handle(&req, &kv_store, &config, &templater).unwrap();

        assert_eq!(res.code, 405);
        assert_eq!(res.headers.get("Allow"), Some(&vec!["POST".to_string()]));

        let state: PendingQrData = kv_store.get("/test/pending_qr_logins/victimkey").unwrap();
        assert!(
            state.session.is_none(),
            "rejected GET must not approve the pending login"
        );
    }

    #[test]
    fn qr_get_still_renders_the_approval_link_for_a_logged_in_session() {
        let byte_kv = Arc::new(MemoryKvStore::default());
        let kv_store = KvStore { byte_kv };
        let templater = Templater::new();
        let config = qr_config();

        let session =
            SessionBuilder::new(crate::IdType::Email, "scanner@example.com").build();
        kv_store.set("/test/sessions/scanner", &session).unwrap();

        // Logged out: redirect to login.
        let logged_out = handle(
            &da_request(
                Some("GET"),
                "http://localhost/decent-auth/qr?key=qkey",
                "",
                None,
            ),
            &kv_store,
            &config,
            &templater,
        )
        .unwrap();
        assert_eq!(logged_out.code, 303);

        // Logged in: render the approval link with POST forms.
        let logged_in = handle(
            &da_request(
                Some("GET"),
                "http://localhost/decent-auth/qr?key=qkey",
                "",
                Some("test_session_key=scanner"),
            ),
            &kv_store,
            &config,
            &templater,
        )
        .unwrap();
        assert_eq!(logged_in.code, 200);
        assert!(logged_in.body.contains("method='POST'"));
        assert!(logged_in.body.contains("/qr/approve"));
    }

    #[test]
    fn qr_approve_and_finalize_still_work_and_finalize_consumes_state() {
        let byte_kv = Arc::new(MemoryKvStore::default());
        let kv_store = KvStore { byte_kv: byte_kv.clone() };
        let templater = Templater::new();
        let config = qr_config();

        let approver_session =
            SessionBuilder::new(crate::IdType::Email, "approver@example.com").build();
        kv_store
            .set("/test/sessions/approver", &approver_session)
            .unwrap();
        kv_store
            .set(
                "/test/pending_qr_logins/qkey",
                PendingQrData {
                    return_target: "/welcome".to_string(),
                    session: None,
                },
            )
            .unwrap();

        let approve_res = handle(
            &da_request(
                Some("POST"),
                "http://localhost/decent-auth/qr/approve",
                "key=qkey",
                Some("test_session_key=approver"),
            ),
            &kv_store,
            &config,
            &templater,
        )
        .unwrap();
        assert_eq!(approve_res.code, 200);

        let approved: PendingQrData = kv_store.get("/test/pending_qr_logins/qkey").unwrap();
        assert!(
            approved.session.is_some(),
            "approval must persist the approver's session"
        );

        let finalize_res = handle(
            &da_request(
                Some("POST"),
                "http://localhost/decent-auth/qr/finalize",
                "key=qkey",
                None,
            ),
            &kv_store,
            &config,
            &templater,
        )
        .unwrap();
        assert_eq!(finalize_res.code, 303);
        assert_eq!(
            finalize_res.headers.get("Location"),
            Some(&vec!["/welcome".to_string()])
        );
        assert!(finalize_res.headers.contains_key("Set-Cookie"));
        assert_eq!(
            session_count(&byte_kv),
            2,
            "approver session plus the newly minted session"
        );

        use crate::kv::Store as _;
        assert!(
            byte_kv.list("/test/pending_qr_logins/").unwrap().is_empty(),
            "successful finalization must consume the pending state"
        );

        // A sequential replay of the same key must fail and mint no session.
        let replay_res = handle(
            &da_request(
                Some("POST"),
                "http://localhost/decent-auth/qr/finalize",
                "key=qkey",
                None,
            ),
            &kv_store,
            &config,
            &templater,
        );
        assert!(replay_res.is_err(), "replayed finalize must fail");
        assert_eq!(
            session_count(&byte_kv),
            2,
            "replayed finalize must not mint another session"
        );
    }
}
