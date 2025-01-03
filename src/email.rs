use std::collections::{HashMap,BTreeMap};
use serde::{Serialize,Deserialize};
use extism_pdk::{host_fn};
use crate::{
    DaHttpRequest,DaHttpResponse,KvStore,Config,error,kv,Url,DaError,
    parse_params,Session,SESSION_PREFIX,generate_random_key,HEADER_TMPL,
    FOOTER_TMPL,get_return_target,CommonTemplateData,
    create_session_cookie,SessionBuilder,IdType,email,
    generate_random_text,
};

const LOGIN_EMAIL_TMPL: &str = include_str!("../templates/login_email.html");
const APPROVE_CODE_TMPL: &str = include_str!("../templates/approve_code.html");

#[derive(Debug,Serialize,Deserialize)]
pub struct SmtpConfig {
    server_address: String,
    server_port: u16,
    username: String,
    password: String,
    sender_email: String,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct Message {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub text: String,
    //pub html: String,
}

#[host_fn]
extern "ExtismHost" {
    fn extism_send_email(email_json: &str); 
}

#[cfg(target_arch = "wasm32")]
pub fn send_email(msg: Message) {
    let json = serde_json::to_string(&msg).expect("to json");
    unsafe { extism_send_email(&json).expect("extism_send_email") };
}


pub fn handle_login<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> 
where T: kv::Store,
{
    let parsed_url = Url::parse(&req.url)?; 
    let host = parsed_url.host().ok_or(DaError::new("Failed to parse host"))?;

    let params = parse_params(&req).unwrap_or(HashMap::new());

    if let Some(email_address) = params.get("email") {

        if let Some(smtp_config) = &config.smtp_config {

            let code = generate_random_key(6).to_lowercase();
            let display_code = format!("{}-{}", &code[0..3], &code[3..6]).to_uppercase();

            let session = SessionBuilder::new(IdType::Email, &email_address)
                .build();

            let key = format!("/{}/{}/{}", config.storage_prefix, "pending_code_login", code);
            kv_store.set(&key, session)?;

            email::send_email(email::Message{
                from: format!("\"{} email validator\" <{}>", host, smtp_config.sender_email),
                to: email_address.to_string(),
                subject: format!("Email validation from {}", host),
                text: format!("This is an email validation request from {}. Use the code below to prove you control {}:\n\n{}", host, email_address, display_code),
            });
        }
        else {
            return Ok(DaHttpResponse::new(400, "No SMTP config"));
        }

        let template = mustache::compile_str(APPROVE_CODE_TMPL)?;
        let data = CommonTemplateData{ 
            config,
            header: HEADER_TMPL,
            footer: FOOTER_TMPL,
            session: None,
            prefix: config.path_prefix.to_string(),
            return_target: get_return_target(&req),
        };
        let body = template.render_to_string(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        Ok(res)
    }
    else if let Some(code) = params.get("code") {

        if code == "" {
            return Ok(DaHttpResponse::new(400, &format!("Invalid code")));
        }

        let code = code.replace("-", "").to_lowercase();

        let key = format!("/{}/{}/{}", config.storage_prefix, "pending_code_login", code);
        let session: Session = kv_store.get(&key)?;
        let _ = kv_store.delete(&key);

        let session_key = generate_random_text();
        let session_cookie = create_session_cookie(&config.storage_prefix, &session_key);

        let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);
        kv_store.set(&kv_session_key, session)?;

        let mut res = DaHttpResponse::new(303, "");

        let return_target = get_return_target(&req);

        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![return_target]),
            ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
        ]);

        return Ok(res);
    }
    else {
        let template = mustache::compile_str(LOGIN_EMAIL_TMPL)?;
        let data = CommonTemplateData{ 
            config,
            header: HEADER_TMPL,
            footer: FOOTER_TMPL,
            session: None,
            prefix: config.path_prefix.to_string(),
            return_target: get_return_target(&req),
        };
        let body = template.render_to_string(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        Ok(res)
    }
}
