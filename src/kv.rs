use std::{fmt};
use serde::{Serialize,Deserialize};

pub trait Store: Sync {
    fn get(&self, key: &str) -> Result<Vec<u8>, Error>;
    fn set(&self, key: &str, value: Vec<u8>) -> Result<(), Error>;
    fn delete(&self, key: &str) -> Result<(), Error>;
    fn list(&self, prefix: &str) -> Result<Vec<String>, Error>;
}

#[derive(Debug,Serialize,Deserialize)]
pub struct Error {
    msg: String
}

impl Error {
    pub fn new(msg: &str) -> Self {
        Self{
            msg: msg.to_string(),
        }
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {}", self.msg)
    }
}
