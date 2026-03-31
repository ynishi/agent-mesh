use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("connection failed: {0}")]
    Connection(String),

    #[error("auth failed: {0}")]
    Auth(String),

    #[error("send failed: {0}")]
    Send(String),

    #[error("receive failed: {0}")]
    Receive(String),

    #[error("timeout waiting for response")]
    Timeout,

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("remote error: {0}")]
    Remote(String),

    #[error("request cancelled")]
    Cancelled,

    #[error("rate limited")]
    RateLimited,
}
