use std::time::Duration;

use easypam::{AuthenticatorBuilder, Message};

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("trace"));
    let authenticator = AuthenticatorBuilder::new().workers(10).build().unwrap();
    for _ in 0..5 {
        let authenticator = authenticator.clone();
        tokio::spawn(async move {
            loop {
                let conversation = authenticator
                    .chat("system-auth", "test")
                    .await
                    .expect("failed to create conversation");
                while let Ok(msg) = conversation.rx().recv().await {
                    match msg {
                        Message::NoEcho(s) if s.starts_with("Password") => {
                            // correct password
                            conversation
                                .tx()
                                .send("xxx".to_string())
                                .await
                                .expect("failed to send password");
                        }
                        Message::Authenticated => {
                            println!("User authenticated");
                            break;
                        }
                        Message::AuthenticationFailed => {
                            println!("Authentication failed (???)");
                            break;
                        }
                        Message::ValidationFailed => {
                            println!("Validation failed");
                            break;
                        }
                        Message::Echo(s) => {
                            println!("Echo: {}", s);
                        }
                        Message::NoEcho(s) => {
                            println!("NoEcho: {}", s);
                        }
                        Message::Info(s) => {
                            println!("Info: {}", s);
                        }
                        Message::Error(s) => {
                            println!("Error: {}", s);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
    }
    for _ in 0..5 {
        let authenticator = authenticator.clone();
        tokio::spawn(async move {
            loop {
                let conversation = authenticator
                    .chat("system-auth", "test")
                    .await
                    .expect("failed to create conversation");
                while let Ok(msg) = conversation.rx().recv().await {
                    match msg {
                        // incorrect password
                        Message::NoEcho(s) if s.starts_with("Password") => {
                            conversation
                                .tx()
                                .send("xx".to_string())
                                .await
                                .expect("failed to send password");
                        }
                        Message::Authenticated => {
                            println!("User authenticated (???)");
                            break;
                        }
                        Message::AuthenticationFailed => {
                            println!("Authentication failed (OK)");
                            break;
                        }
                        Message::ValidationFailed => {
                            println!("Validation failed");
                            break;
                        }
                        Message::Echo(s) => {
                            println!("Echo: {}", s);
                        }
                        Message::NoEcho(s) => {
                            println!("NoEcho: {}", s);
                        }
                        Message::Info(s) => {
                            println!("Info: {}", s);
                        }
                        Message::Error(s) => {
                            println!("Error: {}", s);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
    }
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
