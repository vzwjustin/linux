// SPDX-License-Identifier: GPL-2.0-only

//! Common kallsyms policy helpers.

use core::ffi::{c_int, c_uint};

use kernel::bindings;

const CAP_OPT_NOAUDIT: c_uint = 1 << 1;

#[cfg(CONFIG_PERF_EVENTS)]
unsafe extern "C" {
    static mut sysctl_perf_event_paranoid: c_int;
}

#[inline]
fn kallsyms_for_perf() -> bool {
    #[cfg(CONFIG_PERF_EVENTS)]
    {
        // SAFETY: `sysctl_perf_event_paranoid` is a C global used read-only
        // here, matching the previous C helper.
        unsafe { sysctl_perf_event_paranoid <= 1 }
    }

    #[cfg(not(CONFIG_PERF_EVENTS))]
    {
        false
    }
}

#[inline]
unsafe fn has_syslog_capability(cred: *const bindings::cred) -> bool {
    // SAFETY: This mirrors the previous C call. `cred` is provided by the C
    // caller, and `init_user_ns` is the kernel global namespace object.
    unsafe {
        bindings::security_capable(
            cred,
            core::ptr::addr_of_mut!(bindings::init_user_ns),
            bindings::CAP_SYSLOG as c_int,
            CAP_OPT_NOAUDIT,
        ) == 0
    }
}

#[no_mangle]
/// Returns whether kallsyms values may be shown for the given credentials.
///
/// # Safety
///
/// `cred` must be either null where accepted by the underlying security hook,
/// or a valid pointer to a kernel credential object.
pub unsafe extern "C" fn kallsyms_show_value(cred: *const bindings::cred) -> bool {
    // SAFETY: `kptr_restrict` is a C global read here exactly as in the
    // previous implementation.
    match unsafe { bindings::kptr_restrict } {
        0 => {
            if kallsyms_for_perf() {
                true
            } else {
                // SAFETY: Same preconditions as this exported function.
                unsafe { has_syslog_capability(cred) }
            }
        }
        1 => {
            // SAFETY: Same preconditions as this exported function.
            unsafe { has_syslog_capability(cred) }
        }
        _ => false,
    }
}
