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

#[derive(Debug,Content)]
pub struct TemplateData {
    path_prefix: String,
    return_target: String,
    id: String,
    login_methods: Vec<InternalLoginMethod>,
    method_type: String,
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

    fn render_common(&self, name: &str, data: &TemplateData) -> error::Result<String> {

        let rendered = self.ramhorns.get(name)
            .ok_or(DaError{msg: "Missing template".to_string()})?.render(&data);
        Ok(rendered)
    }
}
