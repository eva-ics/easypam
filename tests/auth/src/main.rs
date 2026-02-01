use std::time::Duration;

use easypam::{AuthenticatorBuilder, Message};

fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("trace"));
    let mut auth_success = false;
    // ensure the authenticator is dropped to see that all threads are cleaned up
    {
        let authenticator = AuthenticatorBuilder::new().workers(4).build().unwrap();
        let conversation = authenticator
            .chat_sync("system-auth", "test")
            .expect("failed to create conversation");
        while let Ok(msg) = conversation.rx().recv_blocking() {
            match msg {
                Message::NoEcho(s) if s.starts_with("Password") => {
                    conversation
                        .tx()
                        .send_blocking("xxx".to_string())
                        .expect("failed to send password");
                }
                Message::NoEcho(s) => {
                    panic!("unexpected noecho message: {}", s);
                }
                Message::Echo(s) => {
                    panic!("unexpected echo message: {}", s);
                }
                Message::Info(s) => {
                    println!("Info: {}", s);
                }
                Message::Error(e) => {
                    eprintln!("Error: {}", e);
                }
                Message::AuthenticationFailed => {
                    panic!("authentication failed");
                }
                Message::ValidationFailed => {
                    panic!("validation failed");
                }
                Message::Authenticated => {
                    auth_success = true;
                    break;
                }
            }
        }
    }
    if auth_success {
        println!("Authentication succeeded");
    } else {
        eprintln!("Something went wrong");
    }
    std::thread::sleep(Duration::from_secs(1));
}
