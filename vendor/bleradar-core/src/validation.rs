//! Shared internal validation helpers used across the engine modules.
//!
//! Every engine module previously carried its own byte-for-byte identical
//! `require_text` free function, differing only in which module-specific
//! error enum it returned. This module keeps the one behavior in one place;
//! each error type opts in with a small [`EmptyValueError`] implementation
//! instead of repeating the validation logic itself.

/// Produces this error type's "empty required text field" variant.
///
/// Implemented by each engine module's error enum so that [`require_text`]
/// can be shared instead of duplicated per module.
pub(crate) trait EmptyValueError {
    /// Builds the empty-value error naming the offending `field`.
    fn empty_value(field: &'static str) -> Self;
}

/// Rejects an empty (after trimming) required text field, otherwise returns it unchanged.
pub(crate) fn require_text<E: EmptyValueError>(
    value: String,
    field: &'static str,
) -> Result<String, E> {
    if value.trim().is_empty() {
        Err(E::empty_value(field))
    } else {
        Ok(value)
    }
}
