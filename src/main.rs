use std::{env, io, time};
use std::io::Read;
use std::ffi::{CStr, CString};
use std::os::raw::{c_int, c_void, c_char};

use json::JsonValue;

use pam_sys::types::{PamHandle, PamItemType, PamReturnCode, PamFlag, PamMessage, PamMessageStyle, PamResponse};

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

fn init_env() {
    if unsafe { libc::isatty(0) } > 0 {
        panic!("this command is not meant to be run from the console");
    }

    unsafe { libc::umask(077) };

    // Force save our default path
    if let Err(_) = env::var("COCKPIT_TEST_KEEP_PATH") {
        env::set_var("PATH", DEFAULT_PATH);
    }

    let mut env_saved: Vec<String> = Vec::new();

    for k in vec!["G_DEBUG", "G_MESSAGES_DEBUG", "G_SLICE", "PATH", "COCKPIT_REMOTE_PEER"] {
        if let Ok(v) = env::var(k) {
            env_saved.push(format!("{}={}", k, v));
        }
    }
    log::debug!("saved environment: {:?}", env_saved);

    if unsafe { libc::geteuid() } == 0 {
        // set a minimal environment
        if unsafe { libc::clearenv() } != 0 {
            panic!("couldn't clear environment");
        }
        env::set_var("PATH", DEFAULT_PATH);

        if unsafe { libc::setgid(0) != 0 || libc::setuid(0) != 0 } {
            panic!("couldn't switch permissions correctly");
        }
    }

    /*
    signal (SIGALRM, SIG_DFL);
    signal (SIGQUIT, SIG_DFL);
    signal (SIGTSTP, SIG_IGN);
    signal (SIGHUP, SIG_IGN);
    signal (SIGPIPE, SIG_IGN);
    */
}

fn cockpit_frame_write(data: &str) {
    let len = data.len();
    assert!(len > 0);
    print!("{}\n{}", len, data);
}
fn cockpit_frame_read() -> Vec<u8> {
    // OK to be panic-y here in c-session
    let mut size = String::new();
    io::stdin().read_line(&mut size).unwrap();
    let size: usize = size.trim_end().parse().unwrap();

    let mut buf = vec![0; size];
    io::stdin().read_exact(&mut buf).unwrap();
    // log::debug!("read frame: {:?}", buf);
    buf
}

fn write_authorize_begin() -> String {
    log::debug!("start building auth challenge");
    let now = time::SystemTime::now().duration_since(time::UNIX_EPOCH)
        .expect("failed to get current time");
    format!("\n{{\"command\":\"authorize\",\"cookie\":\"session{}{}\"",
                         unsafe { libc::getpid() }, now.as_secs())
}

fn write_control_str(auth: &mut String, field: &str, value: &str) {
    auth.push_str(", ");
    auth.push_str(&json::stringify(field));
    auth.push_str(": ");
    auth.push_str(&json::stringify(value));
}

fn write_control_end(mut auth: String) {
    auth.push_str("}\n");
    cockpit_frame_write(&auth);
    log::debug!("finished auth challenge");
}

fn read_authorize_response() -> JsonValue {
    log::debug!("reading authorize message");
    let message = cockpit_frame_read();
    // only support control channel messages with empty channel ID
    assert!(message[0] == '\n' as u8);
    assert!(message[1] == '{' as u8);
    let message_str = String::from_utf8(message).unwrap();
    json::parse(&message_str).unwrap()
}

fn ws_authorize() -> String {
    // Request authorization header
    let mut auth = write_authorize_begin();
    write_control_str(&mut auth, "challenge", "*");
    write_control_end(auth);

    // Get back authorization response
    let authorization = read_authorize_response();
    log::debug!("authorize response: {:?}", authorization);
    if !authorization.has_key("response") {
        panic!("authorize response has no 'response' field");
    }
    authorization["response"].to_string()
}

fn check_pam_err(code: PamReturnCode, error_context: &str) {
    if code == PamReturnCode::SUCCESS {
        return;
    }

    log::debug!("writing init problem {:?}", code);
    log::error!("{}: {}", error_context, code);
    std::process::exit(code as i32);
}

extern "C" fn converse(
    num_msg: c_int,
    msg: *mut *mut PamMessage,
    out_resp: *mut *mut PamResponse,
    mut appdata_ptr: *mut c_void,
) -> c_int {
    let success = true;

    if msg.is_null() || out_resp.is_null() || num_msg == 0 {
        log::error!("PAM converse: invalid arguments");
        return PamReturnCode::BUF_ERR as c_int;
    }

    let resp = unsafe {
        libc::calloc(num_msg as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse
    };
    if resp.is_null() {
        log::error!("PAM converse: Cannot allocate response buffer");
        return PamReturnCode::BUF_ERR as c_int;
    }

    for i in 0..num_msg as isize {
        let m: &mut PamMessage = unsafe { &mut *(*(msg.offset(i)) as *mut PamMessage) };
        let r: &mut PamResponse = unsafe { &mut *(resp.offset(i)) };
        let msg = unsafe { CStr::from_ptr(m.msg) };
        let msg_style = PamMessageStyle::from(m.msg_style);
        log::debug!("PAM converse: msg #{}, style {}, message {:?}, appdata_ptr {:?}", i, msg_style, msg, &appdata_ptr);

        if msg_style == PamMessageStyle::PROMPT_ECHO_OFF && !appdata_ptr.is_null() {
            log::debug!("PAM converse: first PROMPT_ECHO_OFF message, sending password");
            // let password = unsafe { CStr::from_ptr(*(appdata_ptr as *mut *const i8)) };
            // log::debug!("XXX password is {:?}", password );
            // FIXME: Original C code does not duplicate the string; but here that causes PAM to
            // crash with "free(): invalid pointer"
            r.resp = unsafe { libc::strdup (*(appdata_ptr as *mut *mut c_char)) };

            r.resp_retcode = PamReturnCode::SUCCESS as c_int;
            // clear appdata_ptr for the next PROMPT_ECHO_OFF
            appdata_ptr = std::ptr::null_mut();
        }

        match msg_style {
            PamMessageStyle::PROMPT_ECHO_OFF => {
                log::debug!("answering PAM password prompt");
            },
            PamMessageStyle::PROMPT_ECHO_ON => {
                log::debug!("answering PAM echo prompt");
            },
            PamMessageStyle::ERROR_MSG => {
                log::debug!("answering ERROR_MSG prompt");
            },
            PamMessageStyle::TEXT_INFO => {
                log::debug!("answering TEXT_INFO prompt");
            },
        }
    }

    if !success {
        log::debug!("PAM converse: overall failure, clearing resp buffer and fail with CONV_ERR");
        unsafe { libc::free(resp as *mut c_void) };
        return PamReturnCode::CONV_ERR as c_int;
    }

    log::debug!("PAM converse: overall success, returning response buffer");
    unsafe { *out_resp = resp };
    PamReturnCode::SUCCESS as c_int
}

fn open_session(pamh: &mut PamHandle) -> PamReturnCode {
    let mut pam_user_ptr: *const c_void = std::ptr::null();
    check_pam_err(pam_sys::wrapped::get_item(pamh, PamItemType::USER, &mut pam_user_ptr),
                  "couldn't get PAM_USER");
    let pam_user_ptr = pam_user_ptr as *const c_char;
    let pam_user = unsafe { CStr::from_ptr(pam_user_ptr) };
    log::debug!("open_session: PAM_USER {:?}", pam_user);

    let pwd = unsafe{ libc::getpwnam(pam_user_ptr) };
    if pwd.is_null() {
        log::warn!("couldn't load user info for {:?}", pam_user);
        return PamReturnCode::SYSTEM_ERR;
    }
    log::debug!("PAM_USER uid {}", unsafe {*pwd}.pw_uid);

    log::debug!("checking access for {:?}", pam_user);
    let res = pam_sys::wrapped::acct_mgmt(pamh, PamFlag::NONE);
    if res != PamReturnCode::SUCCESS {
        log::warn!("user account acccess failed");
          // We change PAM_AUTH_ERR to PAM_PERM_DENIED so that we can distinguish between
          // failures here and in pam_authenticate.
        if res == PamReturnCode::AUTH_ERR {
            return PamReturnCode::PERM_DENIED;
        }
        return res;
    }

    log::debug!("opening PAM session for {:?}", pam_user);

    pam_sys::wrapped::putenv(pamh, "XDG_SESSION_CLASS=user");
    pam_sys::wrapped::putenv(pamh, "XDG_SESSION_TYPE=web");
    pam_sys::wrapped::putenv(pamh, &format!("HOME={:?}", unsafe {*pwd}.pw_dir));

    let res = pam_sys::wrapped::setcred(pamh, PamFlag::ESTABLISH_CRED);
    if res != PamReturnCode::SUCCESS {
        log::warn!("establishing credentials failed");
        return res;
    }

    let res = pam_sys::wrapped::open_session(pamh, PamFlag::NONE);
    if res != PamReturnCode::SUCCESS {
        log::warn!("couldn't open session");
        return res;
    }

    let res = pam_sys::wrapped::setcred(pamh, PamFlag::REINITIALIZE_CRED);
    if res != PamReturnCode::SUCCESS {
        log::warn!("reinitializing credentials failed");
        return res;
    }

    PamReturnCode::SUCCESS
}

fn perform_basic(rhost: &str, auth: &str) {
    log::debug!("basic authentication with rhost {}, auth {}", &rhost, &auth);
    // The input should be base64 user:password
    let decoded = String::from_utf8(base64::decode(&auth).unwrap()).unwrap();
    let colon_pos = decoded.find(':')
        .expect("authorize response contains no ':' separator");
    let username = &decoded[..colon_pos];
    let password = &decoded[colon_pos+1..];
    log::debug!("basic auth user '{}' pass '{}'", &username, &password);
    if username.len() == 0 || password.len() == 0 {
        panic!("bad basic auth input");
    }

    let password_cptr = password.as_ptr();
    let conv = pam_sys::types::PamConversation { conv: Some(converse), data_ptr: std::ptr::addr_of!(password_cptr) as *mut c_void };
    let mut pamh: *mut PamHandle = std::ptr::null_mut();
    check_pam_err(pam_sys::wrapped::start("cockpit", Some(&username), &conv, &mut pamh),
                  "couldn't start PAM");

    assert!(!pamh.is_null());
    let mut pamh = unsafe { &mut *pamh };

    let rhost_cstring = CString::new(rhost).unwrap();
    check_pam_err(pam_sys::wrapped::set_item(
                      pamh,
                      PamItemType::RHOST,
                      unsafe { &*(rhost_cstring.as_ptr() as *const std::ffi::c_void) }),
                  "couldn't set PAM_RHOST");

    log::debug!("PAM session initialized");
    let res = pam_sys::wrapped::authenticate(pamh, PamFlag::NONE);
    if res == PamReturnCode::SUCCESS {
        log::debug!("PAM session authenticated");
        check_pam_err(open_session(&mut pamh), "PAM opening session failed");
    } else {
        // FIXME: btmp_log()
        check_pam_err(res, "PAM authentication failed");
    }
}

fn main() {
    // FIXME: info by default
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    init_env();

    let rhost = match env::var("COCKPIT_REMOTE_PEER") {
        Ok(val) => val,
        Err(_) => "".to_string(),
    };
    log::debug!("rhost: {}", rhost);

    let authorization = ws_authorize();
    log::debug!("authorize response: {}", authorization);

    if authorization.starts_with("Basic ") {
        perform_basic(&rhost, &authorization[6..]);
    } else {
        panic!("unrecognized authentication method");
    }
}
