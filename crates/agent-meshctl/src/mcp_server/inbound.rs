//! Inbound message queue for receiving mesh agent requests via MCP.
//!
//! When meshd forwards an incoming request to the MCP Adapter's receive endpoint,
//! the message is queued and a oneshot channel waits for the MCP client to call
//! `reply_message`. If no reply arrives within the timeout, an error is returned
//! to meshd (which propagates back to the calling agent).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde::Serialize;
use tokio::sync::{oneshot, Mutex};

/// Default timeout for waiting on a reply from the MCP client.
const DEFAULT_REPLY_TIMEOUT: Duration = Duration::from_secs(25);

/// A received inbound message waiting for the MCP client to process.
#[derive(Debug, Clone, Serialize)]
pub struct InboundMessage {
    /// Unique message ID (used for `reply_message`).
    pub id: String,
    /// Sender agent ID.
    pub from: String,
    /// Requested capability name.
    pub capability: String,
    /// Request payload.
    pub payload: serde_json::Value,
    /// Reception timestamp (unix millis).
    pub received_at: u64,
}

/// Thread-safe inbound message queue.
///
/// Messages arrive from meshd's `forward_to_local` and are held until the MCP
/// client calls `get_messages` + `reply_message`.
#[derive(Clone)]
pub struct InboundQueue {
    /// Messages that have been received but not yet fetched by `get_messages`.
    ready: Arc<Mutex<Vec<InboundMessage>>>,
    /// Messages that have been fetched and are awaiting a reply.
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<serde_json::Value>>>>,
    /// Timeout for waiting on a reply.
    reply_timeout: Duration,
}

impl Default for InboundQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl InboundQueue {
    pub fn new() -> Self {
        Self {
            ready: Arc::new(Mutex::new(Vec::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            reply_timeout: DEFAULT_REPLY_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_timeout(timeout: Duration) -> Self {
        Self {
            ready: Arc::new(Mutex::new(Vec::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            reply_timeout: timeout,
        }
    }

    /// Drain all ready messages. Called by `get_messages` tool.
    pub async fn drain_messages(&self) -> Vec<InboundMessage> {
        let mut ready = self.ready.lock().await;
        std::mem::take(&mut *ready)
    }

    /// Submit a reply for a pending message. Called by `reply_message` tool.
    ///
    /// Returns `true` if the reply was delivered, `false` if the message ID
    /// was not found (expired or already replied).
    pub async fn submit_reply(&self, message_id: &str, payload: serde_json::Value) -> bool {
        let tx = {
            let mut pending = self.pending.lock().await;
            pending.remove(message_id)
        };
        match tx {
            Some(sender) => sender.send(payload).is_ok(),
            None => false,
        }
    }

    /// Push a new inbound message and wait for a reply (called by the receive endpoint).
    ///
    /// Returns the reply payload, or an error JSON if the MCP client doesn't reply in time.
    async fn enqueue_and_wait(
        &self,
        from: String,
        capability: String,
        payload: serde_json::Value,
    ) -> serde_json::Value {
        let id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let (reply_tx, reply_rx) = oneshot::channel();

        let message = InboundMessage {
            id: id.clone(),
            from,
            capability,
            payload,
            received_at: now,
        };

        // 1. Push to ready queue (MCP client will see it via get_messages).
        {
            let mut ready = self.ready.lock().await;
            ready.push(message);
        }

        // 2. Register the reply channel.
        {
            let mut pending = self.pending.lock().await;
            pending.insert(id.clone(), reply_tx);
        }

        // 3. Wait for reply or timeout.
        match tokio::time::timeout(self.reply_timeout, reply_rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => {
                // Channel dropped (shouldn't happen in normal flow).
                self.cleanup(&id).await;
                serde_json::json!({"error": "reply_channel_closed", "message_id": id})
            }
            Err(_) => {
                // Timeout — MCP client didn't reply in time.
                self.cleanup(&id).await;
                serde_json::json!({"error": "reply_timeout", "message_id": id, "timeout_secs": self.reply_timeout.as_secs()})
            }
        }
    }

    /// Remove a message from both ready and pending queues (cleanup on timeout).
    async fn cleanup(&self, id: &str) {
        {
            let mut ready = self.ready.lock().await;
            ready.retain(|m| m.id != id);
        }
        {
            let mut pending = self.pending.lock().await;
            pending.remove(id);
        }
    }
}

// ── Receive HTTP endpoint (meshd forwards here) ─────────────────────────────

/// Handle an incoming request from meshd.
///
/// Enqueues the message, waits for the MCP client to reply, and returns the
/// reply payload as the HTTP response (which meshd sends back through the relay).
async fn receive_handler(
    State(queue): State<InboundQueue>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let from = body
        .get("from")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let capability = body
        .get("capability")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let payload = body.get("payload").cloned().unwrap_or_else(|| body.clone());

    let reply = queue.enqueue_and_wait(from, capability, payload).await;
    (StatusCode::OK, Json(reply))
}

/// Build the receive HTTP router.
pub fn receive_router(queue: InboundQueue) -> Router {
    Router::new()
        .route("/", post(receive_handler))
        .with_state(queue)
}

/// Start the receive HTTP server on the given address.
pub async fn start_receive_server(addr: SocketAddr, queue: InboundQueue) -> anyhow::Result<()> {
    let app = receive_router(queue);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "MCP receive endpoint listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    // ── Unit tests ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn drain_empty_queue() {
        let queue = InboundQueue::new();
        let msgs = queue.drain_messages().await;
        assert!(msgs.is_empty());
    }

    #[tokio::test]
    async fn enqueue_and_reply() {
        let queue = InboundQueue::new();
        let q2 = queue.clone();

        let handle = tokio::spawn(async move {
            q2.enqueue_and_wait(
                "agent-a".into(),
                "echo".into(),
                serde_json::json!({"text": "hello"}),
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let msgs = queue.drain_messages().await;
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].from, "agent-a");
        assert_eq!(msgs[0].capability, "echo");

        let ok = queue
            .submit_reply(&msgs[0].id, serde_json::json!({"reply": "world"}))
            .await;
        assert!(ok);

        let result = handle.await.unwrap();
        assert_eq!(result["reply"], "world");
    }

    #[tokio::test]
    async fn reply_unknown_id_returns_false() {
        let queue = InboundQueue::new();
        let ok = queue
            .submit_reply("nonexistent", serde_json::json!({}))
            .await;
        assert!(!ok);
    }

    #[tokio::test]
    async fn enqueue_timeout_returns_error() {
        let queue = InboundQueue::with_timeout(Duration::from_millis(200));
        let q2 = queue.clone();

        let result = q2
            .enqueue_and_wait("agent-b".into(), "slow".into(), serde_json::json!({}))
            .await;

        assert_eq!(result["error"], "reply_timeout");
        assert!(result.get("message_id").is_some());
    }

    #[tokio::test]
    async fn drain_is_destructive() {
        let queue = InboundQueue::new();
        let q2 = queue.clone();

        // Enqueue without waiting for reply (fire-and-forget for this test).
        tokio::spawn(async move {
            q2.enqueue_and_wait("a".into(), "cap".into(), serde_json::json!({}))
                .await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let first = queue.drain_messages().await;
        assert_eq!(first.len(), 1);

        // Second drain should be empty.
        let second = queue.drain_messages().await;
        assert!(second.is_empty());
    }

    #[tokio::test]
    async fn multiple_messages_drain() {
        let queue = InboundQueue::new();

        for i in 0..3 {
            let q = queue.clone();
            tokio::spawn(async move {
                q.enqueue_and_wait(
                    format!("agent-{i}"),
                    "cap".into(),
                    serde_json::json!({"i": i}),
                )
                .await;
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        let msgs = queue.drain_messages().await;
        assert_eq!(msgs.len(), 3);
    }

    #[tokio::test]
    async fn double_reply_returns_false() {
        let queue = InboundQueue::new();
        let q2 = queue.clone();

        tokio::spawn(async move {
            q2.enqueue_and_wait("a".into(), "cap".into(), serde_json::json!({}))
                .await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let msgs = queue.drain_messages().await;
        let id = &msgs[0].id;

        let first = queue
            .submit_reply(id, serde_json::json!({"ok": true}))
            .await;
        assert!(first);

        let second = queue
            .submit_reply(id, serde_json::json!({"ok": true}))
            .await;
        assert!(!second, "double reply should return false");
    }

    // ── Integration tests (HTTP endpoint) ────────────────────────────────

    /// Helper: build a test request for the receive router.
    fn post_json(body: serde_json::Value) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    /// Full E2E: HTTP POST → get_messages (drain) → reply_message → HTTP response.
    #[tokio::test]
    async fn http_e2e_post_drain_reply() {
        let queue = InboundQueue::new();
        let app = receive_router(queue.clone());

        let body = serde_json::json!({
            "from": "remote-agent-xyz",
            "capability": "summarize",
            "payload": {"text": "hello world"}
        });

        // 1. POST to receive endpoint (blocks until reply or timeout).
        let q = queue.clone();
        let http_handle = tokio::spawn(async move {
            let resp = app.oneshot(post_json(body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 2. Drain messages (simulates MCP get_messages).
        let msgs = q.drain_messages().await;
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].from, "remote-agent-xyz");
        assert_eq!(msgs[0].capability, "summarize");
        assert_eq!(msgs[0].payload["text"], "hello world");

        // 3. Reply (simulates MCP reply_message).
        let ok = q
            .submit_reply(
                &msgs[0].id,
                serde_json::json!({"summary": "greeting detected"}),
            )
            .await;
        assert!(ok);

        // 4. Verify the HTTP response body.
        let resp_body = http_handle.await.unwrap();
        assert_eq!(resp_body["summary"], "greeting detected");
    }

    /// HTTP POST with missing fields uses defaults.
    #[tokio::test]
    async fn http_missing_fields_fallback() {
        let queue = InboundQueue::new();
        let app = receive_router(queue.clone());

        // POST with no from/capability/payload.
        let q = queue.clone();
        let http_handle = tokio::spawn(async move {
            let resp = app
                .oneshot(post_json(serde_json::json!({"arbitrary": "data"})))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let msgs = q.drain_messages().await;
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].from, "unknown");
        assert_eq!(msgs[0].capability, "unknown");
        // payload falls back to the entire body.
        assert_eq!(msgs[0].payload["arbitrary"], "data");

        q.submit_reply(&msgs[0].id, serde_json::json!({"ack": true}))
            .await;
        let resp_body = http_handle.await.unwrap();
        assert_eq!(resp_body["ack"], true);
    }

    /// Multiple concurrent HTTP POSTs are all drained.
    #[tokio::test]
    async fn http_concurrent_posts() {
        let queue = InboundQueue::new();

        let mut handles = Vec::new();
        for i in 0..3 {
            let app = receive_router(queue.clone());
            handles.push(tokio::spawn(async move {
                let body = serde_json::json!({
                    "from": format!("agent-{i}"),
                    "capability": "ping",
                    "payload": {"n": i}
                });
                let resp = app.oneshot(post_json(body)).await.unwrap();
                let bytes = resp.into_body().collect().await.unwrap().to_bytes();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            }));
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Drain all 3.
        let msgs = queue.drain_messages().await;
        assert_eq!(msgs.len(), 3);

        // Reply to each.
        for msg in &msgs {
            let ok = queue
                .submit_reply(&msg.id, serde_json::json!({"pong": msg.payload["n"]}))
                .await;
            assert!(ok);
        }

        // All HTTP responses should complete.
        for h in handles {
            let resp = h.await.unwrap();
            assert!(resp.get("pong").is_some());
        }
    }
}
