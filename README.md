<h2>
  easypam - Rust interface for PAM (Linux)
  <a href="https://crates.io/crates/easypam"><img alt="crates.io page" src="https://img.shields.io/crates/v/easypam.svg"></img></a>
  <a href="https://docs.rs/easypam"><img alt="docs.rs page" src="https://docs.rs/easypam/badge.svg"></img></a>
</h2>


EasyPAM provides high-level versatile interface to PAM (Pluggable
Authentication Modules) library for Rust applications. It simplifies the
process of integrating PAM authentication into Rust programs, making it easier
to manage user authentication and authorization.

EasyPAM claims to be lock-safe (lots of timeout checks inside), thread-safe,
memory-leak-free and code-safe (as much as it is possible when talking to C
libraries).

## Compatibility

EasyPAM works with Linux only. Tested with libpam0g 1.4.0 (Ubuntu 22 LTS) &
1.5.3 (Ubuntu 24 LTS).

The PAM library is loaded **dynamically** in runtime, which allows to use the
crate as an additional authentication method in applications, where the methods
can be chosen by users during configuration, without forcing them to have
compatible PAM module installed in their system.

Dynamic loading also makes much easier compiling the crate for different
platforms.

## Usage

The goal of the library is not to provide `easy PAM authentication` but instead to provide
an `easy access to PAM conversation API`, so that the users of the library can
implement authentication flows for the most possible use-cases.

The API is available for both sync and async applications.

### Example

```rust,no_run
use easypam::{AuthenticatorBuilder, Message};

fn main() {
    let mut auth_success = false;
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
    if auth_success {
        println!("Authentication succeeded");
    } else {
        println!("Something went wrong");
    }
}
```

## References

EasyPAM is a part of [EVA ICS](https://www.eva-ics.com) project.

