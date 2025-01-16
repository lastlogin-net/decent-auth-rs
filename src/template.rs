pub use ramhorns::Content;

use crate::{
    error,DaError,LoginMethod,ATPROTO_STR,FEDIVERSE_STR,ADMIN_CODE_STR,
    QR_CODE_STR,OIDC_STR,EMAIL_STR,FEDCM_STR,Config,
};
use ramhorns::Ramhorns;

const HEADER_TMPL: &str = include_str!("../templates/header.html");
const FOOTER_TMPL: &str = include_str!("../templates/footer.html");
const INDEX_TMPL: &str = include_str!("../templates/index.html");
const LOGIN_TMPL: &str = include_str!("../templates/login.html");
const LOGIN_ATPROTO_TMPL: &str = include_str!("../templates/login_atproto.html");
const LOGIN_FEDIVERSE_TMPL: &str = include_str!("../templates/login_fediverse.html");
const LOGIN_ADMIN_CODE_TMPL: &str = include_str!("../templates/login_admin_code.html");
const LOGIN_QR_CODE_TMPL: &str = include_str!("../templates/login_qr.html");
const QR_LINK_TMPL: &str = include_str!("../templates/qr_link.html");
const QR_APPROVED_TMPL: &str = include_str!("../templates/qr_approved.html");
const LOGIN_EMAIL_TMPL: &str = include_str!("../templates/login_email.html");
const APPROVE_CODE_TMPL: &str = include_str!("../templates/approve_code.html");
const LOGIN_FEDCM_TMPL: &str = include_str!("../templates/login_fedcm.html");
const APPROVE_OAUTH_TMPL: &str = include_str!("../templates/approve_oauth.html");
const ERROR_TMPL: &str = include_str!("../templates/error.html");

#[derive(Debug,Content)]
pub struct TemplateData {
    path_prefix: String,
    return_target: String,
    id: String,
    login_methods: Vec<InternalLoginMethod>,
    method_type: String,
    qr_key: String,
    qr_svg: String,
    pkce_code_challenge: String,
    pkce_code_verifier: String,
    runtime: String,
    client_id: String,
    auth_url: String,
    message: String,
}

pub struct DataBuilder {
    td: TemplateData,
}

impl DataBuilder {
    pub fn new(config: &Config) -> Self {

        let login_methods = config.login_methods.clone().unwrap()
            .iter()
            .map(|m| m.clone().into()).collect();

        Self{
            td: TemplateData{
                path_prefix: config.path_prefix.clone(),
                return_target: "".to_string(),
                id: "".to_string(),
                method_type: "".to_string(),
                login_methods,
                qr_key: "".to_string(),
                qr_svg: "".to_string(),
                pkce_code_challenge: "".to_string(),
                pkce_code_verifier: "".to_string(),
                runtime: config.runtime.clone().unwrap_or("".to_string()),
                client_id: "".to_string(),
                auth_url: "".to_string(),
                message: "".to_string(),
            },
        }
    }

    pub fn return_target(mut self, val: &str) -> Self {
        self.td.return_target = val.to_string();
        self
    }

    pub fn id(mut self, val: &str) -> Self {
        self.td.id = val.to_string();
        self
    }

    pub fn method_type(mut self, val: &str) -> Self {
        self.td.method_type = val.to_string();
        self
    }

    pub fn qr_key(mut self, val: &str) -> Self {
        self.td.qr_key = val.to_string();
        self
    }

    pub fn qr_svg(mut self, val: &str) -> Self {
        self.td.qr_svg = val.to_string();
        self
    }

    pub fn pkce_code_challenge(mut self, val: &str) -> Self {
        self.td.pkce_code_challenge = val.to_string();
        self
    }

    pub fn pkce_code_verifier(mut self, val: &str) -> Self {
        self.td.pkce_code_verifier = val.to_string();
        self
    }

    pub fn client_id(mut self, val: &str) -> Self {
        self.td.client_id = val.to_string();
        self
    }

    pub fn auth_url(mut self, val: &str) -> Self {
        self.td.auth_url = val.to_string();
        self
    }

    pub fn message(mut self, val: &str) -> Self {
        self.td.message = val.to_string();
        self
    }

    pub fn build(self) -> TemplateData {
        self.td
    }
}

#[derive(Debug)]
pub struct IndexPageData<'a> {
    pub config: &'a Config,
    pub return_target: String,
    pub id: String,
}

#[derive(Debug)]
pub struct CommonData<'a> {
    pub config: &'a Config,
    pub return_target: String,
}

pub struct QrData<'a>{
    pub config: &'a Config,
    pub return_target: String,
    pub qr_svg: String,
    pub qr_key: String,
}

pub struct QrLinkData<'a>{
    pub config: &'a Config,
    pub return_target: String,
    pub qr_key: String,
}

pub struct FedCmData<'a> {
    pub config: &'a Config,
    pub return_target: String,
    pub pkce_code_challenge: String,
    pub pkce_code_verifier: String,
}

pub struct OAuth2Data<'a> {
    pub config: &'a Config,
    pub return_target: String,
    pub auth_url: &'a str,
    pub client_id: &'a str,
}

pub struct ErrorData<'a> {
    pub config: &'a Config,
    pub return_target: String,
    pub message: &'a str,
}

#[derive(Debug,Content)]
struct InternalLoginMethod {
    method_type: String,
    name: String,
    uri: String,
}

struct Builder {
    login_method: InternalLoginMethod,
}

impl Builder {
    fn new(r#type: &str) -> Self {
        Self{
            login_method: InternalLoginMethod{
                method_type: r#type.to_string(),
                name: "".to_string(),
                uri: "".to_string(),
            },
        }
    }

    fn name(mut self, name: &str) -> Self {
        self.login_method.name = name.to_string();
        self
    }

    fn uri(mut self, uri: &str) -> Self {
        self.login_method.uri = uri.to_string();
        self
    }

    fn build(self) -> InternalLoginMethod{
        self.login_method
    }
}

impl From<LoginMethod> for InternalLoginMethod {
    fn from(login_method: LoginMethod) -> Self {
        match login_method {
            LoginMethod::AtProto => Builder::new(ATPROTO_STR).build(),
            LoginMethod::Fediverse => Builder::new(FEDIVERSE_STR).build(),
            LoginMethod::AdminCode => Builder::new(ADMIN_CODE_STR).build(),
            LoginMethod::QrCode => Builder::new(QR_CODE_STR).build(),
            LoginMethod::Oidc { name, uri } => Builder::new(OIDC_STR)
                .name(&name)
                .uri(&uri)
                .build(),
            LoginMethod::Email => Builder::new(EMAIL_STR).build(),
            LoginMethod::FedCm => Builder::new(FEDCM_STR).build(),
        }
    }
}

pub struct Templater {
    ramhorns: Ramhorns,
}

impl Templater {
    pub fn new() -> Self {

        let mut ramhorns = Ramhorns::new();
        ramhorns.insert(HEADER_TMPL, "header.html").expect("Failed to get template");
        ramhorns.insert(FOOTER_TMPL, "footer.html").expect("Failed to get template");
        ramhorns.insert(INDEX_TMPL, "index.html").expect("Failed to get template");
        ramhorns.insert(LOGIN_TMPL, "login.html").expect("Failed to get template");
        ramhorns.insert(LOGIN_ATPROTO_TMPL, "login_atproto.html").expect("Failed to get template");
        ramhorns.insert(LOGIN_FEDIVERSE_TMPL, "login_fediverse.html").expect("Failed to get template");
        ramhorns.insert(LOGIN_ADMIN_CODE_TMPL, "login_admin_code.html").expect("Failed to get template");
        ramhorns.insert(LOGIN_QR_CODE_TMPL, "login_qr.html").expect("Failed to get template");
        ramhorns.insert(QR_LINK_TMPL, "qr_link.html").expect("Failed to get template");
        ramhorns.insert(QR_APPROVED_TMPL, "qr_approved.html").expect("Failed to get template");
        ramhorns.insert(LOGIN_EMAIL_TMPL, "login_email.html").expect("Failed to get template");
        ramhorns.insert(APPROVE_CODE_TMPL, "approve_code.html").expect("Failed to get template");
        ramhorns.insert(LOGIN_FEDCM_TMPL, "login_fedcm.html").expect("Failed to get template");
        ramhorns.insert(APPROVE_OAUTH_TMPL, "approve_oauth.html").expect("Failed to get template");
        ramhorns.insert(ERROR_TMPL, "error.html").expect("Failed to get template");

        Self{
            ramhorns,
        }
    }

    pub fn render_index_page(&self, data: &IndexPageData) -> error::Result<String> {

        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .id(&data.id)
            .build();

        let rendered = self.ramhorns.get("index.html")
            .ok_or(DaError{msg: "Missing template".to_string()})?.render(&data);
        Ok(rendered)
    }

    pub fn render_login_page(&self, data: &CommonData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .build();
        self.render_common("login.html", &data)
    }

    pub fn render_atproto_page(&self, data: &CommonData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .method_type(ATPROTO_STR)
            .build();
        self.render_common("login_atproto.html", &data)
    }

    pub fn render_fediverse_page(&self, data: &CommonData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .method_type(FEDIVERSE_STR)
            .build();
        self.render_common("login_fediverse.html", &data)
    }

    pub fn render_admin_code_page(&self, data: &CommonData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .method_type(ADMIN_CODE_STR)
            .build();
        self.render_common("login_admin_code.html", &data)
    }

    pub fn render_qr_code_page(&self, data: &QrData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .method_type(QR_CODE_STR)
            .qr_key(&data.qr_key)
            .qr_svg(&data.qr_svg)
            .build();
        self.render_common("login_qr.html", &data)
    }

    pub fn render_qr_code_link_page(&self, data: &QrLinkData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .method_type(QR_CODE_STR)
            .qr_key(&data.qr_key)
            .build();
        self.render_common("qr_link.html", &data)
    }

    pub fn render_qr_approved_page(&self, data: &CommonData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .method_type(QR_CODE_STR)
            .build();
        self.render_common("qr_approved.html", &data)
    }

    pub fn render_email_page(&self, data: &CommonData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .method_type(EMAIL_STR)
            .build();
        self.render_common("login_email.html", &data)
    }

    pub fn render_approve_code_page(&self, data: &CommonData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .method_type(EMAIL_STR)
            .build();
        self.render_common("approve_code.html", &data)
    }

    pub fn render_fedcm_page(&self, data: &FedCmData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .method_type(FEDCM_STR)
            .pkce_code_challenge(&data.pkce_code_challenge)
            .pkce_code_verifier(&data.pkce_code_verifier)
            .build();
        self.render_common("login_fedcm.html", &data)
    }

    pub fn render_oauth_authorize_page(&self, data: &OAuth2Data) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .client_id(&data.client_id)
            .auth_url(&data.auth_url)
            .build();
        self.render_common("approve_oauth.html", &data)
    }

    pub fn render_error_page(&self, data: &ErrorData) -> error::Result<String> {
        let data = DataBuilder::new(data.config)
            .return_target(&data.return_target)
            .message(&data.message)
            .build();
        self.render_common("error.html", &data)
    }

    fn render_common(&self, name: &str, data: &TemplateData) -> error::Result<String> {

        let rendered = self.ramhorns.get(name)
            .ok_or(DaError{msg: "Missing template".to_string()})?.render(&data);
        Ok(rendered)
    }
}
