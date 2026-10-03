// ENCLAVE PATCH (third_party/PATCHES.md): what this process has handed to
// its mixnet client that hasn't reached the far gateway yet, so it can wait
// for that before exiting (a one-way send is otherwise lost with the
// process). Process-wide: an Enclave process runs one mixnet client.
//
// A message counts 1 from submission (`note_submitted`, by whoever calls
// the client's sender) until the client has prepared it, and each of its
// fragments counts 1 from then until its acknowledgement comes back (or it
// is given up after its retransmissions).

use std::sync::atomic::{AtomicIsize, Ordering};

static OUTSTANDING: AtomicIsize = AtomicIsize::new(0);

/// Messages submitted but not yet prepared, plus fragments sent but not
/// yet acknowledged.
pub fn outstanding() -> usize {
    usize::try_from(OUTSTANDING.load(Ordering::SeqCst)).unwrap_or(0)
}

/// Call before handing a message to the client's sender.
pub fn note_submitted() {
    OUTSTANDING.fetch_add(1, Ordering::SeqCst);
}

/// Call if handing it over failed.
pub fn note_unsubmitted() {
    settle(1);
}

pub(crate) fn add(n: usize) {
    OUTSTANDING.fetch_add(isize::try_from(n).unwrap_or(isize::MAX), Ordering::SeqCst);
}

pub(crate) fn settle(n: usize) {
    OUTSTANDING.fetch_sub(isize::try_from(n).unwrap_or(isize::MAX), Ordering::SeqCst);
}
