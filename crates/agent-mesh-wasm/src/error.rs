use thiserror::Error;

#[derive(Debug, Error)]
pub enum WasmSdkError {
    #[error("connection: {0}")]
    Connection(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("send: {0}")]
    Send(String),
    #[error("receive: {0}")]
    Receive(String),
    #[error("timeout")]
    Timeout,
    #[error("remote: {0}")]
    Remote(String),
}
