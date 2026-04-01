//! # E2E Encryption: Noise Protocol XX
//!
//! Provides end-to-end encrypted communication between agents through
//! untrusted relays. The relay can route messages (it sees `from`/`to`)
//! but cannot read the payload.
//!
//! ## Protocol Choice: Noise_XX
//!
//! - **Pattern**: XX (mutual authentication, both sides send static keys)
//! - **DH**: X25519 (fresh keypair per session)
//! - **Cipher**: ChaChaPoly
//! - **Hash**: BLAKE2s
//! - **Implementation**: `snow` crate (Noise spec rev34)
//!
//! ## Why Noise_XX
//!
//! | Pattern | Initiator knows responder? | Responder knows initiator? | Use case |
//! |---------|---------------------------|---------------------------|----------|
//! | NN      | No                        | No                        | Anonymous |
//! | NK      | Yes                       | No                        | Client knows server |
//! | XX      | No                        | No                        | **Mutual discovery** |
//!
//! In agent-mesh, the initiator (MeshClient) may not have the responder's
//! static key cached yet. XX allows both sides to learn each other's keys
//! during the handshake.
//!
//! ## Identity Binding
//!
//! Noise uses X25519 for DH; agent identity is Ed25519 (signing).
//! These are separate key types. Identity binding is achieved by:
//!
//! 1. Handshake messages are wrapped in signed `MeshEnvelope`s
//! 2. Ed25519 envelope signatures prevent relay MITM
//! 3. X25519 static keys are generated fresh per session (no persistence needed)
//! 4. Forward secrecy via ephemeral keys within each Noise session
//!
//! ## Handshake Flow (3 messages via relay)
//!
//! ```text
//! Initiator (MeshClient)          Relay          Responder (meshd)
//!     |                             |                  |
//!     |-- Envelope(Handshake, e) -->|-- route -------->|
//!     |<- Envelope(Handshake, e,ee,s,es) -|<- route --|
//!     |-- Envelope(Handshake, s,se) ->|-- route ------>|
//!     |                             |                  |
//!     |   [TransportState established - forward secrecy]
//!     |                             |                  |
//!     |-- Envelope(Request, enc) -->|-- route -------->|
//!     |<- Envelope(Response, enc) --|<- route ---------|
//! ```
//!
//! ## Session Management
//!
//! - **MeshClient**: one [`NoiseTransport`] per target agent, created lazily
//!   on first `request()` call to that target
//! - **meshd**: `HashMap<AgentId, NoiseTransport>` caching active sessions
//! - Sessions are dropped on WebSocket disconnect (reconnect = new handshake)
//! - No session resumption in v0.2 (stateless reconnect)
//!
//! ## Envelope Changes (v0.2)
//!
//! - `MessageType::Handshake` added for Noise handshake messages
//! - `encrypted: bool` field on `MeshEnvelope` indicates encrypted payload
//! - Encrypted payload is base64url-encoded ciphertext
//!
//! ## Security Properties
//!
//! - **Confidentiality**: payload encrypted with forward-secret session key
//! - **Authenticity**: Ed25519 envelope signature + Noise static key binding
//! - **Forward secrecy**: ephemeral X25519 keys per handshake
//! - **Replay protection**: Noise nonce counter within session;
//!   envelope `id` + `timestamp` across sessions

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use snow::{Builder, HandshakeState, TransportState};

use crate::error::ProtoError;

/// Noise protocol pattern string.
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum Noise message size (65535 per spec).
const MAX_NOISE_MSG: usize = 65535;

/// Overhead added by ChaChaPoly AEAD tag (16 bytes).
pub const NOISE_TAG_LEN: usize = 16;

/// A Noise keypair (X25519) for use in handshakes.
pub struct NoiseKeypair {
    /// X25519 private key (32 bytes).
    pub private: Vec<u8>,
    /// X25519 public key (32 bytes).
    pub public: Vec<u8>,
}

impl NoiseKeypair {
    /// Generate a fresh X25519 keypair via snow's crypto resolver.
    pub fn generate() -> Result<NoiseKeypair, ProtoError> {
        let builder = Builder::new(NOISE_PARAMS.parse().map_err(noise_err)?);
        let kp = builder.generate_keypair().map_err(noise_err)?;
        Ok(NoiseKeypair {
            private: kp.private,
            public: kp.public,
        })
    }
}

/// Noise handshake state machine.
///
/// Wraps `snow::HandshakeState`. Call [`write_message`](Self::write_message)
/// and [`read_message`](Self::read_message) alternately to progress the
/// XX 3-message handshake. After completion, call [`into_transport`](Self::into_transport).
pub struct NoiseHandshake {
    state: HandshakeState,
    is_initiator: bool,
}

impl NoiseHandshake {
    /// Create an initiator handshake state.
    ///
    /// The initiator sends the first handshake message.
    pub fn new_initiator(keypair: &NoiseKeypair) -> Result<Self, ProtoError> {
        let state = Builder::new(NOISE_PARAMS.parse().map_err(noise_err)?)
            .local_private_key(&keypair.private)
            .build_initiator()
            .map_err(noise_err)?;
        Ok(Self {
            state,
            is_initiator: true,
        })
    }

    /// Create a responder handshake state.
    ///
    /// The responder receives the first handshake message.
    pub fn new_responder(keypair: &NoiseKeypair) -> Result<Self, ProtoError> {
        let state = Builder::new(NOISE_PARAMS.parse().map_err(noise_err)?)
            .local_private_key(&keypair.private)
            .build_responder()
            .map_err(noise_err)?;
        Ok(Self {
            state,
            is_initiator: false,
        })
    }

    /// Write the next handshake message (binary).
    ///
    /// Returns base64url-encoded handshake data to be placed in the
    /// envelope payload.
    pub fn write_message(&mut self) -> Result<String, ProtoError> {
        let mut buf = vec![0u8; MAX_NOISE_MSG];
        let len = self.state.write_message(&[], &mut buf).map_err(noise_err)?;
        Ok(URL_SAFE_NO_PAD.encode(&buf[..len]))
    }

    /// Read a handshake message from the peer.
    ///
    /// `data` is the base64url-encoded handshake data from the envelope payload.
    pub fn read_message(&mut self, data: &str) -> Result<(), ProtoError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(data)
            .map_err(|e| ProtoError::Noise(format!("bad handshake base64: {e}")))?;
        let mut buf = vec![0u8; MAX_NOISE_MSG];
        self.state
            .read_message(&bytes, &mut buf)
            .map_err(noise_err)?;
        Ok(())
    }

    /// Whether the handshake is finished.
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Whether this side is the initiator.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Transition to transport mode after handshake completion.
    ///
    /// Returns a [`NoiseTransport`] that can encrypt/decrypt payloads.
    pub fn into_transport(self) -> Result<NoiseTransport, ProtoError> {
        let transport = self.state.into_transport_mode().map_err(noise_err)?;
        Ok(NoiseTransport {
            transport,
            is_initiator: self.is_initiator,
        })
    }
}

/// Noise transport state for encrypting/decrypting payloads after handshake.
pub struct NoiseTransport {
    transport: TransportState,
    is_initiator: bool,
}

impl NoiseTransport {
    /// Encrypt a JSON payload. Returns base64url-encoded ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<String, ProtoError> {
        let mut buf = vec![0u8; plaintext.len() + NOISE_TAG_LEN];
        let len = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(noise_err)?;
        Ok(URL_SAFE_NO_PAD.encode(&buf[..len]))
    }

    /// Decrypt a base64url-encoded ciphertext. Returns plaintext bytes.
    pub fn decrypt(&mut self, ciphertext_b64: &str) -> Result<Vec<u8>, ProtoError> {
        let ciphertext = URL_SAFE_NO_PAD
            .decode(ciphertext_b64)
            .map_err(|e| ProtoError::Noise(format!("bad ciphertext base64: {e}")))?;
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(&ciphertext, &mut buf)
            .map_err(noise_err)?;
        Ok(buf[..len].to_vec())
    }

    /// Whether this transport was the initiator side.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }
}

fn noise_err(e: snow::Error) -> ProtoError {
    ProtoError::Noise(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generation() {
        let kp = NoiseKeypair::generate().unwrap();
        assert_eq!(kp.private.len(), 32);
        assert_eq!(kp.public.len(), 32);
    }

    #[test]
    fn xx_handshake_and_transport() {
        let init_kp = NoiseKeypair::generate().unwrap();
        let resp_kp = NoiseKeypair::generate().unwrap();

        let mut initiator = NoiseHandshake::new_initiator(&init_kp).unwrap();
        let mut responder = NoiseHandshake::new_responder(&resp_kp).unwrap();

        // XX handshake: 3 messages
        // -> e
        let msg1 = initiator.write_message().unwrap();
        responder.read_message(&msg1).unwrap();

        // <- e, ee, s, es
        let msg2 = responder.write_message().unwrap();
        initiator.read_message(&msg2).unwrap();

        // -> s, se
        let msg3 = initiator.write_message().unwrap();
        responder.read_message(&msg3).unwrap();

        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        // Transition to transport mode.
        let mut init_transport = initiator.into_transport().unwrap();
        let mut resp_transport = responder.into_transport().unwrap();

        // Initiator -> Responder
        let plaintext = b"{\"capability\":\"scheduling\",\"action\":\"list\"}";
        let encrypted = init_transport.encrypt(plaintext).unwrap();
        let decrypted = resp_transport.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // Responder -> Initiator
        let response = b"{\"status\":\"ok\",\"data\":[]}";
        let encrypted = resp_transport.encrypt(response).unwrap();
        let decrypted = init_transport.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, response);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let init_kp = NoiseKeypair::generate().unwrap();
        let resp_kp = NoiseKeypair::generate().unwrap();

        let mut initiator = NoiseHandshake::new_initiator(&init_kp).unwrap();
        let mut responder = NoiseHandshake::new_responder(&resp_kp).unwrap();

        let msg1 = initiator.write_message().unwrap();
        responder.read_message(&msg1).unwrap();
        let msg2 = responder.write_message().unwrap();
        initiator.read_message(&msg2).unwrap();
        let msg3 = initiator.write_message().unwrap();
        responder.read_message(&msg3).unwrap();

        let mut init_transport = initiator.into_transport().unwrap();
        let mut resp_transport = responder.into_transport().unwrap();

        let encrypted = init_transport.encrypt(b"secret data").unwrap();

        // Tamper with ciphertext.
        let mut tampered_bytes = URL_SAFE_NO_PAD.decode(&encrypted).unwrap();
        if let Some(byte) = tampered_bytes.last_mut() {
            *byte ^= 0xff;
        }
        let tampered = URL_SAFE_NO_PAD.encode(&tampered_bytes);

        assert!(resp_transport.decrypt(&tampered).is_err());
    }
}
