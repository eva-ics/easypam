use std::{
    ffi::{CStr, CString, c_void},
    ptr,
    time::Duration,
};

use libc::{c_char, c_int};
use libloading::{Library, Symbol};
use rtsc::channel_async::{Receiver, Sender};
use tracing::{error, trace};

const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 0;
const PAM_ERROR_MSG: c_int = 2;
const PAM_TEXT_INFO: c_int = 3;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Timed out")]
    Timeout,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Access error: {0}")]
    Access(String),
    #[error("Function failed: {0}")]
    Failed(String),
    #[error("Dynamic library error: {0}")]
    Library(#[from] libloading::Error),
}

impl Error {
    fn access<E: std::fmt::Display>(e: E) -> Self {
        Error::Access(e.to_string())
    }
}

#[cfg(feature = "async")]
impl From<tokio::time::error::Elapsed> for Error {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Error::Timeout
    }
}

impl From<oneshot::RecvTimeoutError> for Error {
    fn from(_: oneshot::RecvTimeoutError) -> Self {
        Error::Timeout
    }
}

impl From<oneshot::RecvError> for Error {
    fn from(e: oneshot::RecvError) -> Self {
        Error::Failed(e.to_string())
    }
}

impl From<rtsc::Error> for Error {
    fn from(e: rtsc::Error) -> Self {
        Error::Failed(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[repr(C)]
struct PamHandleT;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<
        extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

#[derive(Clone)]
pub struct Authenticator {
    tx: Sender<PamAuth>,
    timeout: Duration,
}

pub struct AuthenticatorBuilder {
    workers: u32,
    queue_size: usize,
    timeout: Duration,
    chat_timeout: Duration,
}

impl Default for AuthenticatorBuilder {
    fn default() -> Self {
        AuthenticatorBuilder {
            workers: 1,
            queue_size: 10,
            timeout: Duration::from_secs(5),
            chat_timeout: Duration::from_secs(60),
        }
    }
}

impl AuthenticatorBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn workers(mut self, workers: u32) -> Self {
        self.workers = workers;
        self
    }
    pub fn queue_size(mut self, queue_size: usize) -> Self {
        self.queue_size = queue_size;
        self
    }
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    pub fn chat_timeout(mut self, chat_timeout: Duration) -> Self {
        self.chat_timeout = chat_timeout;
        self
    }
    pub fn build(self) -> Result<Authenticator> {
        Authenticator::new(
            self.workers,
            self.queue_size,
            self.timeout,
            self.chat_timeout,
        )
    }
}

impl Authenticator {
    fn new(
        workers: u32,
        queue_size: usize,
        timeout: Duration,
        chat_timeout: Duration,
    ) -> Result<Self> {
        let (tx, rx) = rtsc::channel_async::bounded(queue_size);
        trace!("Starting {} PAM workers", workers);
        for _ in 0..workers {
            let rx = rx.clone();
            std::thread::Builder::new()
                .name("PAMworker".to_owned())
                .spawn(move || {
                    if let Err(e) = pam_worker(rx, timeout, chat_timeout) {
                        error!(error = ?e, "PAM worker exited with error");
                    }
                })?;
        }
        Ok(Authenticator { tx, timeout })
    }
    #[cfg(feature = "async")]
    pub async fn chat<S, L>(&self, service: S, login: L) -> Result<Conversation>
    where
        S: Into<String>,
        L: Into<String>,
    {
        let (res_tx, res_rx) = oneshot::channel();
        let auth = PamAuth {
            service: service.into(),
            login: login.into(),
            res_tx,
        };
        trace!(
            "Sending PAM auth request for service '{}' and user '{}'",
            auth.service, auth.login
        );
        tokio::time::timeout(self.timeout, self.tx.send(auth)).await??;
        trace!("Waiting for PAM conversation");
        tokio::time::timeout(self.timeout, res_rx).await??
    }
    pub fn chat_sync<S, L>(&self, service: S, login: L) -> Result<Conversation>
    where
        S: Into<String>,
        L: Into<String>,
    {
        let (res_tx, res_rx) = oneshot::channel();
        let auth = PamAuth {
            service: service.into(),
            login: login.into(),
            res_tx,
        };
        trace!(
            "Sending PAM auth request for service '{}' and user '{}'",
            auth.service, auth.login
        );
        self.tx.send_blocking_timeout(auth, self.timeout)?;
        trace!("Waiting for PAM conversation");
        res_rx.recv_timeout(self.timeout)?
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Message {
    Echo(String),
    NoEcho(String),
    Info(String),
    Error(String),
    AuthenticationFailed,
    ValidationFailed,
    Authenticated,
}

pub struct Conversation {
    msg_rx: Receiver<Message>,
    input_tx: Sender<String>,
}

struct ConversationPam {
    msg_tx: Sender<Message>,
    input_rx: Receiver<String>,
    timeout: Duration,
    chat_timeout: Duration,
}

impl Conversation {
    pub fn tx(&self) -> &Sender<String> {
        &self.input_tx
    }
    pub fn rx(&self) -> &Receiver<Message> {
        &self.msg_rx
    }
}

struct PamAuth {
    service: String,
    login: String,
    res_tx: oneshot::Sender<Result<Conversation>>,
}

#[allow(clippy::too_many_lines)]
fn pam_worker(rx: Receiver<PamAuth>, timeout: Duration, chat_timeout: Duration) -> Result<()> {
    trace!("Starting PAM worker thread");
    unsafe {
        trace!("Loading libpam");
        let lib = Library::new("libpam.so.0")?;
        trace!("Resolving pam_start");
        let pam_start: Symbol<
            unsafe extern "C" fn(
                *const c_char,
                *const c_char,
                *const PamConv,
                *mut *mut PamHandleT,
            ) -> c_int,
        > = lib.get(b"pam_start\0")?;
        trace!("Resolving pam_authenticate");
        let pam_authenticate: Symbol<unsafe extern "C" fn(*mut PamHandleT, c_int) -> c_int> =
            lib.get(b"pam_authenticate\0")?;
        trace!("Resolving pam_acct_mgmt");
        let pam_acct_mgmt: Symbol<unsafe extern "C" fn(*mut PamHandleT, c_int) -> c_int> =
            lib.get(b"pam_acct_mgmt\0")?;
        trace!("Resolving pam_end");
        let pam_end: Symbol<unsafe extern "C" fn(*mut PamHandleT, c_int) -> c_int> =
            lib.get(b"pam_end\0")?;
        trace!("Entering PAM worker loop");
        while let Ok(auth) = rx.recv_blocking() {
            trace!(
                "Starting PAM conversation for user '{}', service '{}'",
                auth.login, auth.service
            );
            let c_service = match CString::new(auth.service) {
                Ok(s) => s,
                Err(e) => {
                    trace!(error = ?e, "Failed to convert service name to CString");
                    auth.res_tx
                        .send(Err(Error::access("invalid service name")))
                        .ok();
                    continue;
                }
            };
            let c_user = match CString::new(auth.login) {
                Ok(s) => s,
                Err(e) => {
                    trace!(error = ?e, "Failed to convert user name to CString");
                    auth.res_tx
                        .send(Err(Error::access("invalid user name")))
                        .ok();
                    continue;
                }
            };
            let (msg_tx, msg_rx) = rtsc::channel_async::bounded(10);
            let (input_tx, input_rx) = rtsc::channel_async::bounded(10);
            let c = Conversation { msg_rx, input_tx };
            let c_pam = ConversationPam {
                msg_tx,
                input_rx,
                timeout,
                chat_timeout,
            };
            let mut pamh: *mut PamHandleT = ptr::null_mut();
            let c_raw = Box::into_raw(Box::new(c_pam)).cast::<c_void>();
            let conv = PamConv {
                conv: Some(conv),
                appdata_ptr: c_raw,
            };
            trace!("Calling pam_start");
            if pam_start(
                c_service.as_ptr(),
                c_user.as_ptr(),
                &raw const conv,
                &raw mut pamh,
            ) != 0
            {
                pam_end(pamh, 1);
                let _ = Box::from_raw(c_raw.cast::<Conversation>());
                auth.res_tx
                    .send(Err(Error::access("pam_start failed")))
                    .ok();
                continue;
            }
            trace!("PAM conversation started, sending conversation to caller");
            auth.res_tx.send(Ok(c)).ok();
            trace!("Calling pam_authenticate");
            if pam_authenticate(pamh, 0) != 0 {
                pam_end(pamh, 1);
                let c = Box::from_raw(c_raw.cast::<ConversationPam>());
                trace!("Authentication failed");
                c.msg_tx
                    .send_blocking_timeout(Message::AuthenticationFailed, timeout)
                    .ok();
                continue;
            }
            trace!("Calling pam_acct_mgmt");
            if pam_acct_mgmt(pamh, 0) != 0 {
                pam_end(pamh, 1);
                let c = Box::from_raw(c_raw.cast::<ConversationPam>());
                trace!("Account management validation failed");
                c.msg_tx
                    .send_blocking_timeout(Message::ValidationFailed, timeout)
                    .ok();
                continue;
            }
            trace!("Calling pam_end");
            pam_end(pamh, 0);
            trace!("PAM authentication successful");
            let c = Box::from_raw(c_raw.cast::<ConversationPam>());
            c.msg_tx
                .send_blocking_timeout(Message::Authenticated, timeout)
                .ok();
        }
    }
    trace!("PAM worker thread exiting");
    Ok(())
}

#[allow(clippy::too_many_lines)]
extern "C" fn conv(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    macro_rules! abort {
        () => {
            return 19; // PAM_CONV_ERR
        };
    }
    unsafe {
        let num_msg = match usize::try_from(num_msg) {
            Ok(n) => n,
            Err(e) => {
                trace!(error = ?e, "Invalid number of PAM messages: {}", num_msg);
                abort!();
            }
        };
        let c: &ConversationPam = &*appdata_ptr.cast::<ConversationPam>();
        let mut reply_msgs = Vec::with_capacity(num_msg);
        for i in 0..num_msg {
            let m = *msg.add(i);
            let message = match (*m).msg_style {
                PAM_PROMPT_ECHO_OFF => {
                    let prompt = CStr::from_ptr((*m).msg.cast_mut())
                        .to_string_lossy()
                        .into_owned();
                    if let Err(e) = c
                        .msg_tx
                        .send_blocking_timeout(Message::NoEcho(prompt), c.timeout)
                    {
                        trace!(error = ?e, "Failed to send PAM NoEcho message to client");
                        abort!();
                    }
                    match c.input_rx.recv_blocking_timeout(c.chat_timeout) {
                        Ok(input) => input,
                        Err(e) => {
                            trace!(error = ?e, "Failed to receive PAM NoEcho response from client");
                            abort!();
                        }
                    }
                }
                PAM_PROMPT_ECHO_ON => {
                    let prompt = CStr::from_ptr((*m).msg.cast_mut())
                        .to_string_lossy()
                        .into_owned();
                    if let Err(e) = c
                        .msg_tx
                        .send_blocking_timeout(Message::Echo(prompt), c.timeout)
                    {
                        trace!(error = ?e, "Failed to send PAM Echo message to client");
                        abort!();
                    }
                    match c.input_rx.recv_blocking_timeout(c.chat_timeout) {
                        Ok(input) => input,
                        Err(e) => {
                            trace!(error = ?e, "Failed to receive PAM Echo response from client");
                            abort!();
                        }
                    }
                }
                PAM_ERROR_MSG => {
                    let prompt = CStr::from_ptr((*m).msg.cast_mut())
                        .to_string_lossy()
                        .into_owned();
                    if let Err(e) = c
                        .msg_tx
                        .send_blocking_timeout(Message::Error(prompt), c.timeout)
                    {
                        trace!(error = ?e, "Failed to send PAM Error message to client");
                        abort!();
                    }
                    continue;
                }
                PAM_TEXT_INFO => {
                    let prompt = CStr::from_ptr((*m).msg.cast_mut())
                        .to_string_lossy()
                        .into_owned();
                    if let Err(e) = c
                        .msg_tx
                        .send_blocking_timeout(Message::Info(prompt), c.timeout)
                    {
                        trace!(error = ?e, "Failed to send PAM Info message to client");
                        abort!();
                    }
                    continue;
                }
                style => {
                    trace!(style, "Unknown PAM message style");
                    abort!();
                }
            };
            let message = match CString::new(message) {
                Ok(s) => s,
                Err(e) => {
                    trace!(error = ?e, "Failed to convert PAM response to CString");
                    abort!();
                }
            };
            reply_msgs.push(message);
        }
        let replies =
            libc::calloc(num_msg, std::mem::size_of::<PamResponse>()).cast::<PamResponse>();
        if replies.is_null() {
            trace!("Failed to allocate PAM responses");
            abort!();
        }
        for (i, message) in reply_msgs.into_iter().enumerate() {
            (*replies.add(i)).resp = libc::strdup(message.as_ptr());
            (*replies.add(i)).resp_retcode = 0;
        }
        *resp = replies;
        trace!("Provided {} PAM responses", num_msg);
        0 // PAM_SUCCESS
    }
}
