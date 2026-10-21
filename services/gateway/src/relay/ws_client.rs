//! `WsClientTransport`: a [`permaura_relay::RelayTransport`] over a tokio-tungstenite client
//! WebSocket. This is the worker side of the wire; the control-plane hub's server-side transport
//! lives in `services/control-plane`.

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use permaura_relay::{CloseCode, Envelope, RelayError, RelayTransport};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A relay transport that dials the control plane (`ws://` or `wss://`). One JSON [`Envelope`]
/// per text message.
pub struct WsClientTransport {
    ws: Ws,
}

impl WsClientTransport {
    /// Dial the control-plane relay endpoint and complete the WebSocket upgrade.
    pub async fn connect(url: &str) -> Result<Self, RelayError> {
        let (ws, _resp) = connect_async(url)
            .await
            .map_err(|e| RelayError::protocol(format!("relay dial failed: {e}")))?;
        Ok(WsClientTransport { ws })
    }
}

#[async_trait]
impl RelayTransport for WsClientTransport {
    async fn send(&mut self, env: Envelope) -> Result<(), RelayError> {
        let text = serde_json::to_string(&env).map_err(|e| RelayError::protocol(e.to_string()))?;
        self.ws
            .send(Message::Text(text.into()))
            .await
            .map_err(|_| RelayError::ConnectionClosed)
    }

    async fn recv(&mut self) -> Result<Envelope, RelayError> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Text(t))) => {
                    return serde_json::from_str(t.as_str())
                        .map_err(|e| RelayError::protocol(e.to_string()))
                }
                Some(Ok(Message::Binary(b))) => {
                    return serde_json::from_slice(b.as_ref())
                        .map_err(|e| RelayError::protocol(e.to_string()))
                }
                Some(Ok(_)) => continue, // Ping/Pong/raw frames: keep reading.
                Some(Err(_)) | None => return Err(RelayError::ConnectionClosed),
            }
        }
    }

    async fn close(&mut self, _code: CloseCode) -> Result<(), RelayError> {
        let _ = self.ws.close(None).await;
        Ok(())
    }
}
