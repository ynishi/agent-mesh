use std::path::PathBuf;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

/// HTTP client that communicates with the meshd Local API over a Unix Domain Socket.
pub struct MeshdClient {
    sock_path: PathBuf,
}

impl MeshdClient {
    pub fn new(sock_path: PathBuf) -> Self {
        Self { sock_path }
    }

    /// Returns the default socket path: `~/.mesh/meshd.sock`.
    pub fn default_sock_path() -> Result<PathBuf> {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        Ok(PathBuf::from(home).join(".mesh").join("meshd.sock"))
    }

    /// Sends a GET request to `path` and returns `(StatusCode, JSON body)`.
    pub async fn get(&self, path: &str) -> Result<(hyper::StatusCode, serde_json::Value)> {
        self.request("GET", path, None).await
    }

    /// Sends a POST request with a JSON body to `path`.
    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<(hyper::StatusCode, serde_json::Value)> {
        self.request("POST", path, Some(body)).await
    }

    /// Sends a DELETE request to `path`.
    pub async fn delete(&self, path: &str) -> Result<(hyper::StatusCode, serde_json::Value)> {
        self.request("DELETE", path, None).await
    }

    /// Returns `true` if meshd is reachable and `GET /status` returns HTTP 200.
    pub async fn is_alive(&self) -> bool {
        match self.get("/status").await {
            Ok((status, _)) => status.is_success(),
            Err(_) => false,
        }
    }

    /// Internal: opens a new UDS connection, performs HTTP/1.1 handshake, sends the request,
    /// and returns the parsed JSON response.
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<(hyper::StatusCode, serde_json::Value)> {
        let stream = UnixStream::connect(&self.sock_path)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to meshd socket: {}",
                    self.sock_path.display()
                )
            })?;

        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io)
            .await
            .context("HTTP/1.1 handshake with meshd failed")?;

        tokio::spawn(conn);

        let (body_bytes, content_type) = match body {
            Some(json) => {
                let serialized =
                    serde_json::to_vec(json).context("failed to serialize request body")?;
                (Bytes::from(serialized), Some("application/json"))
            }
            None => (Bytes::new(), None),
        };

        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost");

        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }

        let req = builder
            .body(Full::new(body_bytes))
            .context("failed to build HTTP request")?;

        let resp = sender
            .send_request(req)
            .await
            .context("failed to send request to meshd")?;

        let status = resp.status();

        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .context("failed to read response body from meshd")?
            .to_bytes();

        let json: serde_json::Value = if body_bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body_bytes)
                .context("failed to parse JSON response from meshd")?
        };

        Ok((status, json))
    }
}

/// Ensures meshd is running and returns a connected `MeshdClient`.
///
/// 1. Attempts UDS connection (`is_alive()`).
/// 2. On failure: spawns meshd as a background process.
/// 3. Retries up to 10 times with 500 ms intervals (max ~5 seconds total).
pub async fn ensure_meshd(sock_path: Option<PathBuf>) -> Result<MeshdClient> {
    let path = match sock_path {
        Some(p) => p,
        None => MeshdClient::default_sock_path()?,
    };

    let client = MeshdClient::new(path);

    if client.is_alive().await {
        return Ok(client);
    }

    spawn_meshd()?;

    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if client.is_alive().await {
            return Ok(client);
        }
    }

    anyhow::bail!(
        "meshd did not become ready within 5 seconds (socket: {})",
        client.sock_path.display()
    )
}

/// Spawns meshd as a detached background process.
///
/// `meshd` must be available on PATH (install via `cargo install agent-meshd`).
fn spawn_meshd() -> Result<()> {
    std::process::Command::new("agent-meshd")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("failed to start meshd (is it installed? Run: cargo install agent-meshd)")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MeshdClient::default_sock_path ─────────────────────────────────────────

    #[test]
    fn default_sock_path_contains_mesh_dir() {
        // HOME が設定されている環境であれば ~/.mesh/meshd.sock になるはずです。
        let path = MeshdClient::default_sock_path().expect("default_sock_path should succeed");
        assert!(
            path.to_string_lossy().ends_with(".mesh/meshd.sock"),
            "unexpected path: {path:?}"
        );
    }

    #[test]
    fn default_sock_path_uses_home_env() {
        // SAFETY: テスト内の環境変数操作はシリアル実行であれば問題ありません。
        // 元の値を保存してから変更し、テスト後に復元します。
        let original = std::env::var("HOME").ok();
        std::env::set_var("HOME", "/custom/home");

        let path = MeshdClient::default_sock_path().expect("default_sock_path should succeed");
        assert_eq!(path, PathBuf::from("/custom/home/.mesh/meshd.sock"));

        match original {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    // ── MeshdClient::is_alive（ソケット不在ケース）────────────────────────────

    #[cfg(unix)]
    #[tokio::test]
    async fn is_alive_returns_false_when_socket_absent() {
        // 存在しないパスを指定した場合は false が返るはずです。
        let nonexistent = std::env::temp_dir().join("meshctl_test_nonexistent_9f3a.sock");
        // 万一残骸があれば削除しておきます。
        let _ = std::fs::remove_file(&nonexistent);

        let client = MeshdClient::new(nonexistent);
        assert!(
            !client.is_alive().await,
            "is_alive should be false when socket is absent"
        );
    }

    // ── MeshdClient::new ───────────────────────────────────────────────────────

    #[test]
    fn new_stores_sock_path() {
        let path = PathBuf::from("/tmp/test.sock");
        let client = MeshdClient::new(path.clone());
        assert_eq!(client.sock_path, path);
    }
}
