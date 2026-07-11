use thiserror::Error;

/// Errors surfaced by [`crate::WasmMeshClient`] and the JS-facing wrapper.
#[derive(Debug, Error)]
pub enum WasmSdkError {
    /// Failed to establish or maintain the WebSocket connection.
    #[error("connection: {0}")]
    Connection(String),
    /// Noise handshake or signature verification failed.
    #[error("auth: {0}")]
    Auth(String),
    /// Received a message that violates the mesh envelope protocol.
    #[error("protocol: {0}")]
    Protocol(String),
    /// Failed to send a message over the WebSocket.
    #[error("send: {0}")]
    Send(String),
    /// Failed to receive or decode a message from the WebSocket.
    #[error("receive: {0}")]
    Receive(String),
    /// A request did not receive a response within the configured timeout.
    #[error("timeout")]
    Timeout,
    /// The remote agent returned an error response.
    #[error("remote: {0}")]
    Remote(String),
}
