//! Configurable verification policies.
//!
//! A [`VerifyPolicy`] declares which password hashing algorithms are allowed and the maximum cost
//! parameters accepted for each of them.
//!
//! [`crate::verify_password_with_policy`] evaluates the policy immediately after parsing the PHC
//! hash string and *before* any password hashing computation runs. This means hashes using
//! unknown/disabled algorithms or oversized parameters are rejected without ever entering the
//! underlying Argon2, PBKDF2, or scrypt implementations, which prevents maliciously large
//! parameters from causing excessive memory or CPU usage.

use core::fmt;

use password_hash::phc::PasswordHash;

/// Password hashing algorithms known to this crate.
///
/// Variants are only available when the corresponding crate feature is enabled.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// Argon2 (any variant: Argon2d, Argon2i, or Argon2id).
    #[cfg(feature = "argon2")]
    Argon2,

    /// PBKDF2-HMAC-SHA256 or PBKDF2-HMAC-SHA512.
    #[cfg(feature = "pbkdf2")]
    Pbkdf2,

    /// scrypt.
    #[cfg(feature = "scrypt")]
    Scrypt,
}

impl HashAlgorithm {
    /// Get the PHC algorithm identifier prefix associated with this algorithm.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            #[cfg(feature = "argon2")]
            Self::Argon2 => "argon2",
            #[cfg(feature = "pbkdf2")]
            Self::Pbkdf2 => "pbkdf2",
            #[cfg(feature = "scrypt")]
            Self::Scrypt => "scrypt",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Maximum Argon2 cost parameters accepted by a [`VerifyPolicy`].
///
/// Every field is an inclusive upper bound on the corresponding PHC parameter.
#[cfg(feature = "argon2")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Argon2Limits {
    /// Maximum memory size in kibibytes (`m` parameter).
    pub m_cost: u32,

    /// Maximum number of iterations (`t` parameter).
    pub t_cost: u32,

    /// Maximum degree of parallelism (`p` parameter).
    pub p_cost: u32,
}

#[cfg(feature = "argon2")]
impl Argon2Limits {
    /// Conservative default limits: 256 MiB of memory, 8 iterations, 4 lanes.
    pub const DEFAULT: Self = Self {
        m_cost: 256 * 1024,
        t_cost: 8,
        p_cost: 4,
    };
}

#[cfg(feature = "argon2")]
impl Default for Argon2Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Maximum scrypt cost parameters accepted by a [`VerifyPolicy`].
///
/// Every field is an inclusive upper bound on the corresponding PHC parameter.
#[cfg(feature = "scrypt")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScryptLimits {
    /// Maximum log₂ of the work factor `N` (`ln` parameter).
    pub log_n: u8,

    /// Maximum block size (`r` parameter).
    pub r: u32,

    /// Maximum parallelization (`p` parameter).
    pub p: u32,
}

#[cfg(feature = "scrypt")]
impl ScryptLimits {
    /// Conservative default limits: `ln <= 20` (N = 1,048,576), `r <= 16`, `p <= 4`.
    pub const DEFAULT: Self = Self {
        log_n: 20,
        r: 16,
        p: 4,
    };
}

#[cfg(feature = "scrypt")]
impl Default for ScryptLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Maximum PBKDF2 cost parameters accepted by a [`VerifyPolicy`].
#[cfg(feature = "pbkdf2")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Pbkdf2Limits {
    /// Maximum number of iterations (`i` parameter).
    pub rounds: u32,
}

#[cfg(feature = "pbkdf2")]
impl Pbkdf2Limits {
    /// Conservative default limit of 1,000,000 iterations.
    pub const DEFAULT: Self = Self { rounds: 1_000_000 };
}

#[cfg(feature = "pbkdf2")]
impl Default for Pbkdf2Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Configurable policy describing which algorithms and parameter costs are accepted when verifying
/// password hashes.
///
/// A `None` entry disables the corresponding algorithm entirely: hashes using it are rejected with
/// [`crate::VerifyError::AlgorithmDisabled`].
///
/// Use [`VerifyPolicy::new`] for a permissive, safe default policy (every enabled algorithm is
/// allowed with its default cost caps), or construct the struct directly to customize or disable
/// individual algorithms.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerifyPolicy {
    /// Allowed Argon2 algorithms and their maximum cost parameters.
    #[cfg(feature = "argon2")]
    pub argon2: Option<Argon2Limits>,

    /// Allowed PBKDF2 algorithms and their maximum cost parameters.
    #[cfg(feature = "pbkdf2")]
    pub pbkdf2: Option<Pbkdf2Limits>,

    /// Allowed scrypt algorithms and their maximum cost parameters.
    #[cfg(feature = "scrypt")]
    pub scrypt: Option<ScryptLimits>,
}

impl VerifyPolicy {
    /// Create a new policy which allows every enabled algorithm with its default cost limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "argon2")]
            argon2: Some(Argon2Limits::DEFAULT),
            #[cfg(feature = "pbkdf2")]
            pbkdf2: Some(Pbkdf2Limits::DEFAULT),
            #[cfg(feature = "scrypt")]
            scrypt: Some(ScryptLimits::DEFAULT),
        }
    }

    /// Classify the algorithm used by a parsed PHC hash.
    ///
    /// Returns `None` if the algorithm is unknown to this crate (or its crate feature isn't
    /// enabled).
    pub(crate) fn classify(hash: &PasswordHash) -> Option<HashAlgorithm> {
        let ident = hash.algorithm.as_str();

        #[cfg(feature = "argon2")]
        if ident == argon2::ARGON2D_IDENT.as_str()
            || ident == argon2::ARGON2I_IDENT.as_str()
            || ident == argon2::ARGON2ID_IDENT.as_str()
        {
            return Some(HashAlgorithm::Argon2);
        }

        #[cfg(feature = "pbkdf2")]
        if ident == pbkdf2::Algorithm::Pbkdf2Sha256.to_str()
            || ident == pbkdf2::Algorithm::Pbkdf2Sha512.to_str()
        {
            return Some(HashAlgorithm::Pbkdf2);
        }

        #[cfg(feature = "scrypt")]
        if ident == scrypt::phc::ALG_ID.as_str() {
            return Some(HashAlgorithm::Scrypt);
        }

        // Suppress unused-variable warnings when no algorithm features are compiled in.
        let _ = ident;
        None
    }

    /// Whether the given algorithm is enabled by this policy.
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "consistent method receiver"
    )]
    pub(crate) fn is_allowed(&self, algorithm: HashAlgorithm) -> bool {
        match algorithm {
            #[cfg(feature = "argon2")]
            HashAlgorithm::Argon2 => self.argon2.is_some(),
            #[cfg(feature = "pbkdf2")]
            HashAlgorithm::Pbkdf2 => self.pbkdf2.is_some(),
            #[cfg(feature = "scrypt")]
            HashAlgorithm::Scrypt => self.scrypt.is_some(),
        }
    }

    /// Parse the hash parameters and ensure they stay within the configured cost limits.
    ///
    /// This runs before any password hashing computation, so oversized parameters never reach the
    /// underlying implementations.
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "consistent method receiver"
    )]
    pub(crate) fn check_limits(&self, hash: &PasswordHash, algorithm: HashAlgorithm) -> bool {
        match algorithm {
            #[cfg(feature = "argon2")]
            HashAlgorithm::Argon2 => {
                let Some(limits) = self.argon2 else {
                    return false;
                };

                let Ok(params) = argon2::Params::try_from(hash) else {
                    return false;
                };

                params.m_cost() <= limits.m_cost
                    && params.t_cost() <= limits.t_cost
                    && params.p_cost() <= limits.p_cost
            }

            #[cfg(feature = "pbkdf2")]
            HashAlgorithm::Pbkdf2 => {
                let Some(limits) = self.pbkdf2 else {
                    return false;
                };

                let Ok(params) = pbkdf2::Params::try_from(hash) else {
                    return false;
                };

                params.rounds() <= limits.rounds
            }

            #[cfg(feature = "scrypt")]
            HashAlgorithm::Scrypt => {
                let Some(limits) = self.scrypt else {
                    return false;
                };

                let Ok(params) = scrypt::Params::try_from(hash) else {
                    return false;
                };

                params.log_n() <= limits.log_n && params.r() <= limits.r && params.p() <= limits.p
            }
        }
    }
}
