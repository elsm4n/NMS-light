use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, header::SEC_WEBSOCKET_PROTOCOL},
    response::Response,
};
use serde_json::json;
use tokio::sync::broadcast;

use crate::{error::ApiError, state::AppState};

const EVENT_PROTOCOL: &str = "cue-events-v1";
const TICKET_PREFIX: &str = "cue-ticket.";

pub async fn upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let offered = headers
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)?
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    if !offered.iter().any(|protocol| *protocol == EVENT_PROTOCOL) {
        return Err(ApiError::Unauthorized);
    }
    let ticket = offered
        .iter()
        .find_map(|protocol| protocol.strip_prefix(TICKET_PREFIX))
        .ok_or(ApiError::Unauthorized)?;
    let _user = state
        .consume_ws_ticket(ticket)
        .await
        .ok_or(ApiError::Unauthorized)?;

    let receiver = state.events.subscribe();
    let shutdown = state.shutdown.clone();
    Ok(websocket
        .protocols([EVENT_PROTOCOL])
        .on_upgrade(move |socket| stream_events(socket, receiver, shutdown)))
}

async fn stream_events(
    mut socket: WebSocket,
    mut receiver: broadcast::Receiver<serde_json::Value>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
            message = socket.recv() => {
                match message {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                }
            }
            event = receiver.recv() => {
                let value = match event {
                    Ok(value) => value,
                    Err(broadcast::error::RecvError::Lagged(lost)) => json!({
                        "type": "stream.gap",
                        "data": {"lost_messages": lost, "recovery": "fetch a fresh REST snapshot"}
                    }),
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if socket.send(Message::Text(value.to_string().into())).await.is_err() {
                    break;
                }
            }
        }
    }
}
