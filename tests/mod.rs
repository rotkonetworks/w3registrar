pub const WS_ADDRESS: &str = "ws://127.0.0.1:8080";

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
enum VerifyIdentity {
    VerifyIdentity,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct ErrorResponse {
    version: String,
    #[serde(rename = "type")]
    _type: VerifyIdentity,
    payload: String,
}

mod test {
    use futures_util::{SinkExt, StreamExt};
    use serde_json::to_string_pretty;
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    use crate::WS_ADDRESS;

    #[tokio::test]
    async fn main_rout() {
        let wallet_id: String = String::from("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty");
        let (ws_stream, _) = connect_async(WS_ADDRESS).await.expect("Failed to connect");
        let (mut rx, mut tx) = ws_stream.split();
        let subscribe_account_state_msg = to_string_pretty(&serde_json::json!({
            "version": "1.0",
            "type": "SubscribeAccountState",
            "payload": wallet_id,
        }))
        .unwrap();
        println!("seinding: {}\n", subscribe_account_state_msg);
        rx.send(Message::from(subscribe_account_state_msg))
            .await
            .unwrap();
        while let stream = tx.next().await {
            match stream {
                Some(data) => {
                    if let Ok(msg) = data {
                        println!("recived: {}\n", msg);
                        break;
                    }
                }
                None => {}
            }
        }
        let request_verification_challange_msg = to_string_pretty(&serde_json::json!({
            "version": "1.0",
            "type": "RequestVerificationChallenge",
            "payload": {
                "wallet_id": wallet_id,
                "field": "Discord",
            },
        }))
        .unwrap();
        println!("sending: {}\n", request_verification_challange_msg);
        rx.send(Message::from(request_verification_challange_msg))
            .await
            .unwrap();
        while let stream = tx.next().await {
            match stream {
                Some(data) => {
                    if let Ok(msg) = data {
                        println!("recived: {}\n", msg);
                        break;
                    }
                }
                None => {}
            }
        }
    }

    #[tokio::test]
    async fn subscribe_account_state() {
        let wallet_id: String = String::from("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty");
        let (ws_stream, _) = connect_async(WS_ADDRESS).await.expect("Failed to connect");
        let (mut rx, mut tx) = ws_stream.split();
        let subscribe_account_state_msg = to_string_pretty(&serde_json::json!({
            "version": "1.0",
            "type": "SubscribeAccountState",
            "payload": wallet_id,
        }))
        .unwrap();
        println!("seinding: {}\n", subscribe_account_state_msg);
        rx.send(Message::from(subscribe_account_state_msg))
            .await
            .unwrap();
        while let stream = tx.next().await {
            match stream {
                Some(data) => {
                    if let Ok(msg) = data {
                        println!("recived: {}\n", msg);
                        break;
                    }
                }
                None => {}
            }
        }
    }

    #[tokio::test]
    async fn failing_rout() {
        let wallet_id: String = String::from("5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy");
        let (ws_stream, _) = connect_async(WS_ADDRESS).await.expect("Failed to connect");
        let (mut rx, mut tx) = ws_stream.split();
        let subscribe_account_state_msg = to_string_pretty(&serde_json::json!({
            "version": "1.0",
            "type": "SubscribeAccountState",
            "payload": wallet_id,
        }))
        .unwrap();
        println!("seinding: {}\n", subscribe_account_state_msg);
        rx.send(Message::from(subscribe_account_state_msg))
            .await
            .unwrap();
        while let stream = tx.next().await {
            match stream {
                Some(data) => {
                    if let Ok(msg) = data {
                        println!("recived: {}\n", msg);
                        break;
                    }
                }
                None => {}
            }
        }
        let verify_identity_msg = to_string_pretty(&serde_json::json!({
            "version": "1.0",
            "type": "VerifyIdentity",
            "payload": {
                "account": wallet_id,
                "field": "Email",
                "challenge": "asdf1234",
            },
        }))
        .unwrap();
        println!("seinding: {}\n", verify_identity_msg);
        rx.send(Message::from(verify_identity_msg)).await.unwrap();
        while let stream = tx.next().await {
            match stream {
                Some(data) => {
                    if let Ok(msg) = data {
                        println!("recived: {}\n", msg);
                        break;
                    }
                }
                None => {}
            }
        }
    }
}
