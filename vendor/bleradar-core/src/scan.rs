//! What the scan does when the platform fails it: the rule the Android layer
//! consults from `ScanCallback.onScanFailed`.
//!
//! Registering a BLE scan is asynchronous — `startScan` returns before the
//! platform has decided — so the only word on a refusal arrives later, as an
//! error code. The app used to log that code and go on believing it was
//! scanning. The rule here decides, for each code and for how many failures of
//! the same incident have already been retried, whether the scan is in fact
//! running, should be started again (and after how long), or is not going to
//! start:
//!
//! * a **permanent** refusal (the device's Bluetooth cannot scan at all) is not
//!   retried;
//! * a **transient** one — the Bluetooth stack that has only just come up
//!   refusing the registration, an internal error, a controller out of
//!   resources, and any code this table does not know — is retried with
//!   exponential backoff, a bounded number of times, so a stack that is only
//!   slow recovers by itself and one that is gone does not keep the radio
//!   busy forever;
//! * the platform's own rate limit (five scan starts per 30 seconds per app)
//!   is retried only after its window has passed, and only twice;
//! * "already started" means the scan **is** running, so nothing is restarted.
//!
//! The rule is total and pure: any code and any count give an answer, and for
//! every code the answer is [`ScanFailureAction::GiveUp`] from some count on,
//! so an incident always ends.

/// `ScanCallback.SCAN_FAILED_ALREADY_STARTED`.
pub const SCAN_FAILED_ALREADY_STARTED: i32 = 1;
/// `ScanCallback.SCAN_FAILED_APPLICATION_REGISTRATION_FAILED`.
pub const SCAN_FAILED_APPLICATION_REGISTRATION_FAILED: i32 = 2;
/// `ScanCallback.SCAN_FAILED_INTERNAL_ERROR`.
pub const SCAN_FAILED_INTERNAL_ERROR: i32 = 3;
/// `ScanCallback.SCAN_FAILED_FEATURE_UNSUPPORTED`.
pub const SCAN_FAILED_FEATURE_UNSUPPORTED: i32 = 4;
/// `ScanCallback.SCAN_FAILED_OUT_OF_HARDWARE_RESOURCES`.
pub const SCAN_FAILED_OUT_OF_HARDWARE_RESOURCES: i32 = 5;
/// `ScanCallback.SCAN_FAILED_SCANNING_TOO_FREQUENTLY`.
pub const SCAN_FAILED_SCANNING_TOO_FREQUENTLY: i32 = 6;

/// How many times a transient failure of one incident is retried before the
/// scan gives up.
pub const MAX_SCAN_RETRIES: u32 = 5;
/// The delay before the first retry of a transient failure.
pub const SCAN_RETRY_BASE_MS: u32 = 1_000;
/// The longest delay before any retry of a transient failure.
pub const SCAN_RETRY_CAP_MS: u32 = 16_000;
/// The delay before retrying a refusal for scanning too frequently: the
/// platform's 30-second window, and a second more.
pub const SCAN_RATE_LIMIT_RETRY_MS: u32 = 31_000;
/// How many times a refusal for scanning too frequently is retried.
pub const MAX_SCAN_RATE_LIMIT_RETRIES: u32 = 2;

/// What to do about a reported scan failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanFailureAction {
    /// The platform says this scan is already running: there is nothing to restart.
    AlreadyRunning,
    /// Start the scan again after this many milliseconds.
    Retry {
        /// The delay.
        after_millis: u32,
    },
    /// Stop trying: the refusal is permanent, or the retries of this incident are spent.
    GiveUp,
}

/// What to do after the platform reported `error_code` (an
/// `android.bluetooth.le.ScanCallback.SCAN_FAILED_*` value, or anything else)
/// for a scan whose earlier failures of the same incident were already
/// retried `retries_so_far` times.
///
/// # Examples
/// ```
/// use bleradar_core::{ScanFailureAction, scan_failure_action};
/// // A registration the stack refused is tried again, each time after longer…
/// assert_eq!(
///     scan_failure_action(2, 0),
///     ScanFailureAction::Retry { after_millis: 1_000 }
/// );
/// assert_eq!(
///     scan_failure_action(2, 3),
///     ScanFailureAction::Retry { after_millis: 8_000 }
/// );
/// // …until the retries are spent; a permanent refusal is never retried.
/// assert_eq!(scan_failure_action(2, 5), ScanFailureAction::GiveUp);
/// assert_eq!(scan_failure_action(4, 0), ScanFailureAction::GiveUp);
/// // "Already started" means it is running.
/// assert_eq!(scan_failure_action(1, 0), ScanFailureAction::AlreadyRunning);
/// ```
#[must_use]
pub const fn scan_failure_action(error_code: i32, retries_so_far: u32) -> ScanFailureAction {
    match error_code {
        SCAN_FAILED_ALREADY_STARTED => ScanFailureAction::AlreadyRunning,
        SCAN_FAILED_FEATURE_UNSUPPORTED => ScanFailureAction::GiveUp,
        SCAN_FAILED_SCANNING_TOO_FREQUENTLY => {
            if retries_so_far < MAX_SCAN_RATE_LIMIT_RETRIES {
                ScanFailureAction::Retry {
                    after_millis: SCAN_RATE_LIMIT_RETRY_MS,
                }
            } else {
                ScanFailureAction::GiveUp
            }
        }
        // Registration failed, internal error, out of hardware resources, and
        // every code this table does not know: transient until proven otherwise.
        _ => {
            if retries_so_far < MAX_SCAN_RETRIES {
                // `retries_so_far < MAX_SCAN_RETRIES`, so the shift cannot overflow.
                let backoff = SCAN_RETRY_BASE_MS << retries_so_far;
                ScanFailureAction::Retry {
                    after_millis: if backoff < SCAN_RETRY_CAP_MS {
                        backoff
                    } else {
                        SCAN_RETRY_CAP_MS
                    },
                }
            } else {
                ScanFailureAction::GiveUp
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code an implementation could plausibly be handed: the six the
    /// platform defines, the values around them, and the extremes.
    fn codes() -> Vec<i32> {
        let mut codes: Vec<i32> = (-3..=12).collect();
        codes.extend([i32::MIN, i32::MAX, 127, 255, 256, -128]);
        codes
    }

    #[test]
    fn the_platforms_own_codes_keep_their_documented_values() {
        // android.bluetooth.le.ScanCallback, API 21 (1-4) and 26/30 (5, 6).
        assert_eq!(
            [
                SCAN_FAILED_ALREADY_STARTED,
                SCAN_FAILED_APPLICATION_REGISTRATION_FAILED,
                SCAN_FAILED_INTERNAL_ERROR,
                SCAN_FAILED_FEATURE_UNSUPPORTED,
                SCAN_FAILED_OUT_OF_HARDWARE_RESOURCES,
                SCAN_FAILED_SCANNING_TOO_FREQUENTLY,
            ],
            [1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn every_incident_ends_and_no_delay_exceeds_its_bound() {
        for code in codes() {
            let mut ended_at = None;
            for retries in 0..=64_u32 {
                match scan_failure_action(code, retries) {
                    ScanFailureAction::Retry { after_millis } => {
                        assert!(
                            ended_at.is_none(),
                            "code {code}: a retry at {retries} after the incident ended"
                        );
                        assert!(after_millis > 0, "code {code}: a zero delay is a busy loop");
                        assert!(
                            after_millis <= SCAN_RATE_LIMIT_RETRY_MS,
                            "code {code}: {after_millis} ms"
                        );
                    }
                    ScanFailureAction::GiveUp => {
                        ended_at.get_or_insert(retries);
                    }
                    ScanFailureAction::AlreadyRunning => {
                        assert_eq!(code, SCAN_FAILED_ALREADY_STARTED);
                    }
                }
            }
            if code != SCAN_FAILED_ALREADY_STARTED {
                assert!(ended_at.is_some(), "code {code} is retried forever");
            }
        }
        // And the extreme counts are answered, not overflowed.
        for code in codes() {
            let _ = scan_failure_action(code, u32::MAX);
        }
    }

    #[test]
    fn a_transient_failure_backs_off_exponentially_up_to_the_cap() {
        for code in [
            SCAN_FAILED_APPLICATION_REGISTRATION_FAILED,
            SCAN_FAILED_INTERNAL_ERROR,
            SCAN_FAILED_OUT_OF_HARDWARE_RESOURCES,
        ] {
            let delays: Vec<ScanFailureAction> = (0..=MAX_SCAN_RETRIES)
                .map(|n| scan_failure_action(code, n))
                .collect();
            assert_eq!(
                delays,
                [
                    ScanFailureAction::Retry {
                        after_millis: 1_000
                    },
                    ScanFailureAction::Retry {
                        after_millis: 2_000
                    },
                    ScanFailureAction::Retry {
                        after_millis: 4_000
                    },
                    ScanFailureAction::Retry {
                        after_millis: 8_000
                    },
                    ScanFailureAction::Retry {
                        after_millis: 16_000
                    },
                    ScanFailureAction::GiveUp,
                ],
                "code {code}"
            );
        }
    }

    #[test]
    fn a_code_the_table_does_not_know_is_treated_as_transient_and_bounded() {
        for code in [0, 7, 8, 99, -1, i32::MIN, i32::MAX] {
            assert_eq!(
                scan_failure_action(code, 0),
                ScanFailureAction::Retry {
                    after_millis: 1_000
                },
                "code {code}"
            );
            assert_eq!(
                scan_failure_action(code, MAX_SCAN_RETRIES),
                ScanFailureAction::GiveUp
            );
        }
    }

    #[test]
    fn a_permanent_refusal_is_never_retried_and_a_running_scan_is_never_restarted() {
        for retries in [0, 1, 5, u32::MAX] {
            assert_eq!(
                scan_failure_action(SCAN_FAILED_FEATURE_UNSUPPORTED, retries),
                ScanFailureAction::GiveUp
            );
            assert_eq!(
                scan_failure_action(SCAN_FAILED_ALREADY_STARTED, retries),
                ScanFailureAction::AlreadyRunning
            );
        }
    }

    #[test]
    fn the_rate_limit_is_waited_out_and_retried_only_twice() {
        let window = ScanFailureAction::Retry {
            after_millis: SCAN_RATE_LIMIT_RETRY_MS,
        };
        assert_eq!(
            scan_failure_action(SCAN_FAILED_SCANNING_TOO_FREQUENTLY, 0),
            window
        );
        assert_eq!(
            scan_failure_action(SCAN_FAILED_SCANNING_TOO_FREQUENTLY, 1),
            window
        );
        assert_eq!(
            scan_failure_action(SCAN_FAILED_SCANNING_TOO_FREQUENTLY, 2),
            ScanFailureAction::GiveUp
        );
        // Longer than the 30 s window the platform counts starts in.
        const { assert!(SCAN_RATE_LIMIT_RETRY_MS > 30_000) };
    }
}
