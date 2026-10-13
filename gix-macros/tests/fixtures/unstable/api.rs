#[gix_macros::unstable]
pub mod plumbing {
    pub fn raw() -> usize {
        42
    }
}

/// File-backed module documentation is preserved.
#[gix_macros::unstable(reason = "This file-backed module still exposes plumbing.")]
pub mod module;

/// Bare gates also work on file-backed modules.
#[gix_macros::unstable]
#[path = "module.rs"]
pub mod module_without_reason;

#[gix_macros::unstable()]
pub struct Raw(pub usize);

#[gix_macros::unstable_fields]
pub struct Handle {
    #[unstable(reason = "The field exposes plumbing state.")]
    pub raw: Raw,
    #[unstable]
    pub raw_without_reason: Raw,
    #[unstable()]
    pub raw_without_reason_with_parens: Raw,
    pub stable: usize,
}

impl Handle {
    pub fn new() -> Self {
        Self {
            raw: Raw(plumbing::raw()),
            raw_without_reason: Raw(module_without_reason::raw()),
            raw_without_reason_with_parens: Raw(42),
            stable: 1,
        }
    }

    pub fn stable(&self) -> usize {
        self.raw() + self.individual() + self.without_reason() + Self::WITHOUT_REASON
    }

    #[gix_macros::unstable]
    pub fn individual(&self) -> usize {
        self.raw.0
    }
}

#[gix_macros::unstable(reason = "These methods expose plumbing state.")]
impl Handle {
    pub fn raw(&self) -> usize {
        self.raw.0
    }
}

#[gix_macros::unstable]
impl Handle {
    pub const WITHOUT_REASON: usize = 1;

    pub fn without_reason(&self) -> usize {
        self.raw_without_reason.0 + self.raw_without_reason_with_parens.0
    }
}

#[gix_macros::unstable]
impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.raw.0.fmt(f)
    }
}
