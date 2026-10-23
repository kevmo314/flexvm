//! Changes go through the commands: this binary, run with the server's `--state` and `--run`, as a user
//! would run it. Their failures (`flexvm: ...` on stderr) become docker's errors, by what they say.

use std::process::Stdio;

use hyper::StatusCode;

use super::{Api, Error};

/// What a command printed, once it exited 0.
pub struct Output {
    pub stdout: Vec<u8>,
}

impl Api {
    /// `flexvm GLOBALS WORDS...`: nothing on stdin, killed if dropped before it ends.
    pub fn command<S: AsRef<std::ffi::OsStr>>(&self, words: &[S]) -> tokio::process::Command {
        // This binary even if it was replaced on disk: what serves and what it runs agree.
        let mut cmd = tokio::process::Command::new("/proc/self/exe");
        cmd.args(&self.globals).args(words).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        cmd
    }

    /// Runs the command to its end: its stdout, or its failure as docker's error.
    pub async fn run<S: AsRef<std::ffi::OsStr>>(&self, words: &[S]) -> Result<Output, Error> {
        let out = self.command(words).output().await?;
        match out.status.success() {
            true => Ok(Output { stdout: out.stdout }),
            false => Err(failure(&out.stderr)),
        }
    }
}

/// A command's failure, from the last thing it said on stderr (its `flexvm: ` error line).
pub fn failure(stderr: &[u8]) -> Error {
    let text = String::from_utf8_lossy(stderr);
    let line = text.lines().rev().map(str::trim).find(|l| !l.is_empty()).unwrap_or("the command failed");
    let message = line.strip_prefix("flexvm: ").unwrap_or(line).to_string();
    Error::new(status_of(&message), message)
}

/// Docker's status for what a command failed with: a missing VM or image is 404, a VM in the wrong state
/// 409, a bad setting 400; anything else the server's own failure.
pub fn status_of(message: &str) -> StatusCode {
    const MISSING: &[&str] = &["no vm named", "no vms named", "no image", "no such", "not found", "is not pulled"];
    const CONFLICT: &[&str] = &[
        "is running",
        "not running",
        "is paused",
        "is stopped",
        "has exited",
        "has failed",
        "is lost",
        "is starting",
        "is used by",
        "in use",
        "already",
        "is taken",
        "taken meanwhile",
        "moved to",
        "moved away",
        "migration in progress",
        "is the source of",
        "meanwhile",
    ];
    const BAD: &[&str] = &["bad ", "needs ", "does not apply", "must ", "is not supported", "are not supported", "takes no", "not both", "give "];
    let m = message.to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| m.contains(w));
    match () {
        _ if has(MISSING) => StatusCode::NOT_FOUND,
        _ if has(CONFLICT) => StatusCode::CONFLICT,
        _ if has(BAD) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_read_as_docker_errors() {
        let e = failure(b"some progress\nflexvm: no vm named \"web\"\n\n");
        assert_eq!((e.status, e.message.as_str()), (StatusCode::NOT_FOUND, "no vm named \"web\""));
        assert_eq!(failure(b"flexvm: vm web is running: stop or kill it first, or flexvm rm -f web\n").status, StatusCode::CONFLICT);
        assert_eq!(failure(b"flexvm: bad --memory \"x\": give a size, as 512m or 2g").status, StatusCode::BAD_REQUEST);
        assert_eq!(failure(b"flexvm: vm web did not suspend (it runs on); see /run/flexvm/vms/web.log").status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(failure(b"").message, "the command failed");
        // Said by something else than flexvm: as it is.
        assert_eq!(failure(b"thread 'main' panicked\n").message, "thread 'main' panicked");
    }
}
