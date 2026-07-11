//! [`SdkError`], the SDK's error surface.

use thiserror::Error;

/// Errors that can occur when using [`MeshClient`](crate::MeshClient) or
/// [`MeshAgent`](crate::MeshAgent).
#[derive(Debug, Error)]
pub enum SdkError {
    /// The WebSocket connection to the relay could not be established.
    #[error("connection failed: {0}")]
    Connection(String),

    /// The relay challenge-response (or session resume) handshake failed.
    #[error("auth failed: {0}")]
    Auth(String),

    /// Writing a message to the WebSocket sink failed.
    #[error("send failed: {0}")]
    Send(String),

    /// Reading or decoding a message from the WebSocket stream failed.
    #[error("receive failed: {0}")]
    Receive(String),

    /// No response was received for a request within the caller's timeout.
    ///
    /// A `Cancel` envelope is sent to the target agent when this occurs.
    #[error("timeout waiting for response")]
    Timeout,

    /// A wire-level or Noise protocol operation failed (e.g. envelope
    /// (de)serialization, missing Noise session, encrypt/decrypt failure).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// The remote agent's handler returned an error response.
    #[error("remote error: {0}")]
    Remote(String),

    /// The request was cancelled before a response arrived. Reserved for
    /// callers that want to surface cancellation as an error variant.
    #[error("request cancelled")]
    Cancelled,

    /// The relay or remote agent rejected the request due to rate limiting.
    /// Reserved for callers/relay implementations that enforce rate limits.
    #[error("rate limited")]
    RateLimited,
}
