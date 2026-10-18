//! Included by both the host (flexvm/src/guest.rs) and the guest agent, so they cannot drift apart.

pub const PORT: u32 = 52;
/// Host port the guest asks for memory on (`<vsock uds>_53` on the host).
pub const MEM_PORT: u32 = 53;

/// Reply frames are `[kind u8][len u32 LE][payload]`.
pub const FRAME_STDOUT: u8 = 1;
pub const FRAME_STDERR: u8 = 2;
pub const FRAME_EXIT: u8 = 3;
pub const FRAME_MSG: u8 = 4;
pub const FRAME_LOST: u8 = 5;

/// Optional client acknowledgement after receiving FRAME_EXIT: release the finished session.
pub const SESSION_DONE: u8 = b'd';

pub const MAX_BODY: usize = 1024 * 1024;

/// In a refusal that a moment later may not recur (a busy agent, a checkpointing VM): the host
/// tries the request again rather than give up.
pub const TRY_AGAIN: &str = "; try again";

/// Free MiB kept plugged for `total` MiB: the host plugs more below it, the guest throttles past it.
pub fn headroom(total: u64) -> u64 {
    (total / 4).max(1024.min(total / 2))
}

pub fn valid_session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[allow(dead_code)] // The host only writes frames in tests.
pub fn write_frame(mut w: impl std::io::Write, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&frame(kind, &[payload]))
}

/// Builds a frame directly from its payload parts, without an intermediate payload buffer.
pub fn frame(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().map(|p| p.len()).sum::<usize>();
    let mut frame = Vec::with_capacity(5 + len);
    frame.push(kind);
    frame.extend_from_slice(&(len as u32).to_le_bytes());
    parts.iter().for_each(|p| frame.extend_from_slice(p));
    frame
}

/// Ends the refusal of a command that could not be run with the status its client exits with, as
/// docker exec does: 127 when it is not found, 126 when it cannot be run (or its user or directory).
pub const EXIT_STATUS: &str = "; exit status ";

/// The status an `EXIT_STATUS` refusal carries, and the message without it.
pub fn refusal_status(m: &str) -> Option<(i32, &str)> {
    let (m, code) = m.rsplit_once(EXIT_STATUS)?;
    Some((code.parse().ok()?, m))
}

/// An `ARGV` session's command, with no shell: its body is NUL-terminated fields, each a tag byte
/// and its value. `a` an argument (in order), `e` K=V, `w` the working directory, `u` USER[:GROUP],
/// `d` (no value) detach.
#[derive(Debug, Default, PartialEq)]
pub struct Exec {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub workdir: Option<String>,
    pub user: Option<String>,
    pub detach: bool,
}

impl Exec {
    pub fn encode(&self) -> Result<String, String> {
        let mut body = String::new();
        let fields = self.argv.iter().map(|v| ('a', v)).chain(self.env.iter().map(|v| ('e', v)));
        let fields = fields.chain(self.workdir.iter().map(|v| ('w', v))).chain(self.user.iter().map(|v| ('u', v)));
        for (tag, value) in fields {
            if value.contains('\0') {
                return Err(format!("{value:?} contains a nul byte"));
            }
            body.push(tag);
            body.push_str(value);
            body.push('\0');
        }
        if self.detach {
            body.push_str("d\0");
        }
        Ok(body)
    }

    #[allow(dead_code)] // The host decodes only in tests.
    pub fn decode(body: &str) -> Result<Self, String> {
        let mut e = Exec::default();
        let fields = body.strip_suffix('\0').ok_or("unterminated exec field")?;
        for field in fields.split('\0') {
            let value = field.get(1..).unwrap_or_default().to_string();
            match field.as_bytes().first() {
                Some(b'a') => e.argv.push(value),
                Some(b'e') => e.env.push(value),
                Some(b'w') => e.workdir = Some(value),
                Some(b'u') => e.user = Some(value),
                Some(b'd') if value.is_empty() => e.detach = true,
                _ => return Err(format!("bad exec field {field:?}")),
            }
        }
        Ok(e)
    }
}
