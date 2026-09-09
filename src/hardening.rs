//! Process-wide hardening applied before any key material is fetched.
//!
//! These stop a *plaintext seed in RAM* from being copied somewhere durable or
//! readable. They are cheap and they close real paths, but note what they are
//! not: they do not defend against the operator of the machine. That is
//! Confidential Space's job.

/// What actually took effect. Log this rather than assuming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    /// `RLIMIT_CORE = 0`: the kernel will not write a core file for us.
    pub core_dumps_disabled: bool,
    /// `PR_SET_DUMPABLE = 0`: no core file, and `/proc/self/mem` and friends
    /// become root-owned, so a same-uid process cannot read our memory.
    pub not_dumpable: bool,
    /// A debugger is currently attached. If this is true when keys are about
    /// to be loaded, something is wrong.
    pub traced: bool,
}

/// Apply hardening. Best-effort by design: a failure to set a limit must not
/// stop a validator from booting, so the outcome is reported, not thrown.
pub fn harden_process(set_not_dumpable: bool) -> HardeningReport {
    let core_dumps_disabled = disable_core_dumps();
    let not_dumpable = if set_not_dumpable {
        set_undumpable()
    } else {
        false
    };
    HardeningReport {
        core_dumps_disabled,
        not_dumpable,
        traced: is_traced(),
    }
}

fn disable_core_dumps() -> bool {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a fully initialised, correctly typed rlimit and
    // RLIMIT_CORE is a valid resource id.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 }
}

#[cfg(target_os = "linux")]
fn set_undumpable() -> bool {
    // SAFETY: PR_SET_DUMPABLE takes one integer argument and ignores the rest.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 }
}

#[cfg(not(target_os = "linux"))]
fn set_undumpable() -> bool {
    false
}

/// Read `TracerPid` from `/proc/self/status`. Advisory only — a determined
/// tracer can hide — but it catches an accidentally attached debugger, and a
/// `strace` on the node would otherwise see every seed byte. An unreadable
/// `/proc` reads as "not traced": this is a diagnostic, not a gate.
fn is_traced() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("TracerPid:"))
                .and_then(|pid| pid.trim().parse::<i64>().ok())
        })
        .is_some_and(|pid| pid != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_core_dumps_disabled() {
        // Deliberately does not set PR_SET_DUMPABLE: that is irreversible for
        // the test process and would break the rest of the suite's /proc reads.
        let report = harden_process(false);
        assert!(report.core_dumps_disabled);
        assert!(!report.not_dumpable);
    }

    #[test]
    fn trace_detection_reads_proc() {
        // Under `cargo test` nothing is attached.
        assert!(!is_traced());
    }
}
