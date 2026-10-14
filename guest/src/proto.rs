//! Shared by the host (flexvm/src/guest.rs) and the guest agent, which both
//! include this file, so the two sides cannot drift apart.

/// Guest port the agent serves requests on.
pub const PORT: u32 = 52;
/// Host port the guest asks for memory on (`<vsock uds>_53` on the host).
pub const MEM_PORT: u32 = 53;

/// Reply frames are `[kind u8][len u32 LE][payload]`.
pub const FRAME_STDOUT: u8 = 1;
pub const FRAME_STDERR: u8 = 2;
pub const FRAME_EXIT: u8 = 3;
pub const FRAME_MSG: u8 = 4;
/// Session output before this offset is gone.
pub const FRAME_LOST: u8 = 5;

/// Longest command body (and frame payload).
pub const MAX_BODY: usize = 1024 * 1024;

/// Free memory (MiB) kept plugged for a guest with `total` MiB: the host
/// plugs more below it, and the guest throttles allocations that outrun it.
pub fn headroom(total: u64) -> u64 {
    (total / 4).max(1024.min(total / 2))
}

pub fn valid_session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
