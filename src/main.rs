use std::{env, io, time};
use std::io::Read;

use json::JsonValue;

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

fn init_env() {
    if unsafe { libc::isatty(0) } > 0 {
        panic!("this command is not meant to be run from the console");
    }

    nc::umask(077).unwrap();

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

    if nc::geteuid() == 0 {
        // set a minimal environment
        if unsafe { libc::clearenv() } != 0 {
            panic!("couldn't clear environment");
        }
        env::set_var("PATH", DEFAULT_PATH);

        nc::setgid(0).expect("failed to set group ID");
        nc::setuid(0).expect("failed to set user ID");
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
                         nc::getpid(), now.as_secs())
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

fn perform_basic(rhost: &str, auth: &str) {
    log::debug!("basic authentication with rhost {}, auth {}", &rhost, &auth);
    let decoded = String::from_utf8(base64::decode(&auth).unwrap()).unwrap();
    let colon_pos = decoded.find(':')
        .expect("authorize response contains no ':' separator");
    let username = &decoded[..colon_pos];
    let password = &decoded[colon_pos+1..];
    log::debug!("basic auth user '{}' pass '{}'", &username, &password);
    if username.len() == 0 || password.len() == 0 {
        panic!("bad basic auth input");
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
