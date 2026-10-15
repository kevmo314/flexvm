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

pub const MAX_BODY: usize = 1024 * 1024;

/// Free MiB kept plugged for `total` MiB: the host plugs more below it, the guest throttles past it.
pub fn headroom(total: u64) -> u64 {
    (total / 4).max(1024.min(total / 2))
}

pub fn valid_session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[allow(dead_code)] // The host only writes frames in tests.
pub fn write_frame(mut w: impl std::io::Write, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&[&[kind][..], &(payload.len() as u32).to_le_bytes()].concat())?;
    w.write_all(payload)
}
