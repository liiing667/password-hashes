#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

extern crate alloc;

mod errors;
mod policy;

pub use crate::errors::{ParseError, VerifyError};
#[cfg(feature = "argon2")]
pub use crate::policy::Argon2Limits;
#[cfg(feature = "pbkdf2")]
pub use crate::policy::Pbkdf2Limits;
#[cfg(feature = "scrypt")]
pub use crate::policy::ScryptLimits;
pub use crate::policy::{HashAlgorithm, VerifyPolicy};

use alloc::string::{String, ToString};
use password_hash::{
    PasswordHasher, PasswordVerifier,
    phc::{ParamsString, PasswordHash},
};

#[cfg(not(any(feature = "argon2", feature = "pbkdf2", feature = "scrypt")))]
compile_error!(
    "please enable at least one password hash crate feature, e.g. argon2, pbkdf2, scrypt"
);

#[cfg(feature = "argon2")]
use argon2::Argon2;
#[cfg(feature = "pbkdf2")]
use pbkdf2::Pbkdf2;
#[cfg(feature = "scrypt")]
use scrypt::Scrypt;

/// Generate a password hash for the given password.
///
/// Uses the best available password hashing algorithm given the enabled crate features (typically
/// Argon2 unless explicitly disabled).
#[allow(clippy::missing_panics_doc, reason = "shouldn't panic in practice")]
pub fn generate_hash(password: impl AsRef<[u8]>) -> String {
    generate_phc_hash(password.as_ref())
        .as_ref()
        .map(ToString::to_string)
        .expect("password hashing error")
}

/// Generate a PHC hash using the preferred algorithm.
#[allow(unreachable_code)]
fn generate_phc_hash(password: &[u8]) -> password_hash::Result<PasswordHash> {
    //
    // Algorithms below are in order of preference
    //
    #[cfg(feature = "argon2")]
    return Argon2::default().hash_password(password);

    #[cfg(feature = "scrypt")]
    return Scrypt::default().hash_password(password);

    #[cfg(feature = "pbkdf2")]
    return Pbkdf2::default().hash_password(password);
}

/// Verify the provided password against the provided password hash.
///
/// # Errors
/// Returns `Err(VerifyError)` if the hash didn't parse successfully or the password failed to
/// verify against the hash.
pub fn verify_password(password: impl AsRef<[u8]>, hash: &str) -> Result<(), VerifyError> {
    let hash = PasswordHash::new(hash).map_err(ParseError::new)?;

    let algs: &[&dyn PasswordVerifier<PasswordHash>] = &[
        #[cfg(feature = "argon2")]
        &Argon2::default(),
        #[cfg(feature = "pbkdf2")]
        &Pbkdf2::default(),
        #[cfg(feature = "scrypt")]
        &Scrypt::default(),
    ];

    for &alg in algs {
        if alg.verify_password(password.as_ref(), &hash).is_ok() {
            return Ok(());
        }
    }

    Err(VerifyError::PasswordInvalid)
}

/// Outcome of a policy-aware password verification.
///
/// Returned by [`verify_password_with_policy`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyOutcome {
    /// Algorithm used by the verified hash.
    pub algorithm: HashAlgorithm,

    /// Whether the hash should be rehashed because it isn't using the recommended algorithm and
    /// parameters.
    ///
    /// Uses the same criteria as [`is_hash_obsolete`].
    pub rehash_required: bool,
}

/// Verify the provided password against the provided password hash, enforcing the given
/// verification [`VerifyPolicy`].
///
/// The PHC hash is parsed first, then the policy is evaluated *before* any password hashing
/// computation runs:
/// - [`VerifyError::UnknownAlgorithm`] if the algorithm is unknown or its crate feature isn't
///   enabled.
/// - [`VerifyError::AlgorithmDisabled`] if the algorithm is disabled by the policy.
/// - [`VerifyError::ParamsExceedLimit`] if the parameters can't be parsed or exceed the policy
///   cost limits.
///
/// Only hashes which pass the policy are verified, and the final comparison is performed using the
/// constant-time comparison provided by the underlying `password-hash` crates.
///
/// On success the [`VerifyOutcome`] reports the parsed [`HashAlgorithm`] and whether the hash is
/// obsolete (i.e. needs rehashing via [`generate_hash`]).
///
/// # Errors
/// Returns [`VerifyError::Parse`] if the hash could not be parsed as a PHC string, the policy
/// errors described above, or [`VerifyError::PasswordInvalid`] if the password did not match.
pub fn verify_password_with_policy(
    password: impl AsRef<[u8]>,
    hash: &str,
    policy: &VerifyPolicy,
) -> Result<VerifyOutcome, VerifyError> {
    let hash = PasswordHash::new(hash).map_err(ParseError::new)?;

    let algorithm = VerifyPolicy::classify(&hash).ok_or(VerifyError::UnknownAlgorithm)?;

    if !policy.is_allowed(algorithm) {
        return Err(VerifyError::AlgorithmDisabled);
    }

    if !policy.check_limits(&hash, algorithm) {
        return Err(VerifyError::ParamsExceedLimit);
    }

    let valid = match algorithm {
        #[cfg(feature = "argon2")]
        HashAlgorithm::Argon2 => Argon2::default()
            .verify_password(password.as_ref(), &hash)
            .is_ok(),
        #[cfg(feature = "pbkdf2")]
        HashAlgorithm::Pbkdf2 => Pbkdf2::default()
            .verify_password(password.as_ref(), &hash)
            .is_ok(),
        #[cfg(feature = "scrypt")]
        HashAlgorithm::Scrypt => Scrypt::default()
            .verify_password(password.as_ref(), &hash)
            .is_ok(),
    };

    if !valid {
        return Err(VerifyError::PasswordInvalid);
    }

    Ok(VerifyOutcome {
        algorithm,
        rehash_required: is_obsolete(&hash),
    })
}

/// Determine if the given password hash is using the recommended algorithm and parameters.
///
/// This can be used by implementations which wish to lazily update their password hashes (i.e. by
/// rehashing the password with [`generate_hash`]) to determine if such an update should be applied.
///
/// When the hash parses successfully, it will return one of the following:
/// - `Ok(true)` if the hash *isn't* using the latest recommended algorithm/parameters.
/// - `Ok(false)` if the hash *is* using the latest recommended algorithm/parameters.
///
/// # Errors
/// Returns `Err(ParseError)` if the hash could not be parsed.
#[allow(unreachable_code, reason = "feature gating")]
pub fn is_hash_obsolete(hash: &str) -> Result<bool, ParseError> {
    let hash = PasswordHash::new(hash).map_err(ParseError::new)?;
    Ok(is_obsolete(&hash))
}

#[allow(unreachable_code, reason = "feature gating")]
fn is_obsolete(hash: &PasswordHash) -> bool {
    #[cfg(feature = "argon2")]
    return hash.algorithm != argon2::Algorithm::default().ident()
        || hash.params != default_params_string::<argon2::Params>();

    #[cfg(feature = "scrypt")]
    return hash.algorithm != scrypt::phc::ALG_ID
        || hash.params != default_params_string::<scrypt::Params>();

    #[cfg(feature = "pbkdf2")]
    return hash.algorithm != pbkdf2::Algorithm::default().into()
        || hash.params != default_params_string::<pbkdf2::Params>();

    true
}

fn default_params_string<T>() -> ParamsString
where
    T: Default + TryInto<ParamsString, Error = password_hash::Error>,
{
    T::default().try_into().expect("invalid default params")
}

#[cfg(test)]
mod tests {
    use super::{generate_hash, is_hash_obsolete, verify_password};

    const EXAMPLE_PASSWORD: &str = "password";

    #[test]
    fn happy_path() {
        let hash = generate_hash(EXAMPLE_PASSWORD);
        assert!(verify_password(EXAMPLE_PASSWORD, &hash).is_ok());
        assert!(verify_password("bogus", &hash).is_err());
        assert!(!is_hash_obsolete(&hash).expect("hash can be parsed"));
    }

    #[cfg(feature = "argon2")]
    mod argon2 {
        use super::{EXAMPLE_PASSWORD, verify_password};

        /// Argon2 hash for the string "password".
        const EXAMPLE_HASH: &str = "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo";

        #[test]
        fn verify() {
            assert!(verify_password(EXAMPLE_PASSWORD, EXAMPLE_HASH).is_ok());
            assert!(verify_password("bogus", EXAMPLE_HASH).is_err());
        }
    }

    #[cfg(feature = "pbkdf2")]
    mod pdkdf2 {
        use super::verify_password;

        /// PBKDF2 password test vector from the `pbkdf2` crate
        const EXAMPLE_PASSWORD: &[u8] = b"passwordPASSWORDpassword";

        /// PBKDF2 hash test vector from the `pbkdf2` crate
        const EXAMPLE_HASH: &str = "$pbkdf2-sha256$i=4096,l=40\
            $c2FsdFNBTFRzYWx0U0FMVHNhbHRTQUxUc2FsdFNBTFRzYWx0\
            $NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q";

        #[test]
        fn verify() {
            assert!(verify_password(EXAMPLE_PASSWORD, EXAMPLE_HASH).is_ok());
            assert!(verify_password("bogus", EXAMPLE_HASH).is_err());
        }
    }

    #[cfg(feature = "scrypt")]
    mod scrypt {
        use super::{EXAMPLE_PASSWORD, verify_password};

        /// scrypt hash for the string "password".
        const EXAMPLE_HASH: &str = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

        #[test]
        fn verify() {
            assert!(verify_password(EXAMPLE_PASSWORD, EXAMPLE_HASH).is_ok());
            assert!(verify_password("bogus", EXAMPLE_HASH).is_err());
        }
    }

    mod policy {
        use super::{generate_hash, is_hash_obsolete};
        use crate::{VerifyError, VerifyPolicy, verify_password_with_policy};

        const PASSWORD: &str = "password";

        #[test]
        fn default_policy_accepts_generated_hash() {
            let hash = generate_hash(PASSWORD);
            let outcome =
                verify_password_with_policy(PASSWORD, &hash, &VerifyPolicy::new()).unwrap();

            assert!(!outcome.rehash_required);
            assert_eq!(outcome.rehash_required, is_hash_obsolete(&hash).unwrap());

            assert_eq!(
                verify_password_with_policy("bogus", &hash, &VerifyPolicy::new()),
                Err(VerifyError::PasswordInvalid)
            );
        }

        #[test]
        fn unknown_algorithm_is_rejected_before_computation() {
            // Syntactically valid PHC string using an algorithm this crate doesn't implement.
            let hash = "$yescrypt$ln=16$c29tZXNhbHQ$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

            assert_eq!(
                verify_password_with_policy(PASSWORD, hash, &VerifyPolicy::new()),
                Err(VerifyError::UnknownAlgorithm)
            );
        }

        #[test]
        fn parse_errors_are_preserved() {
            assert!(matches!(
                verify_password_with_policy(PASSWORD, "not a phc string", &VerifyPolicy::new()),
                Err(VerifyError::Parse(_))
            ));
        }

        #[cfg(feature = "argon2")]
        mod argon2 {
            use super::{PASSWORD, verify_password_with_policy};
            use crate::{Argon2Limits, HashAlgorithm};
            use crate::{VerifyError, VerifyPolicy};

            /// Argon2 hash for the string "password".
            const EXAMPLE_HASH: &str = "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo";

            #[test]
            fn verifies_and_reports_algorithm_and_rehash() {
                let outcome =
                    verify_password_with_policy(PASSWORD, EXAMPLE_HASH, &VerifyPolicy::new())
                        .unwrap();

                assert_eq!(outcome.algorithm, HashAlgorithm::Argon2);
                // Argon2i with non-default parameters is obsolete relative to Argon2id defaults.
                assert!(outcome.rehash_required);
            }

            #[test]
            fn disabled_algorithm_is_rejected() {
                let policy = VerifyPolicy {
                    argon2: None,
                    ..VerifyPolicy::new()
                };

                assert_eq!(
                    verify_password_with_policy(PASSWORD, EXAMPLE_HASH, &policy),
                    Err(VerifyError::AlgorithmDisabled)
                );
            }

            #[test]
            fn oversized_memory_is_rejected_without_computation() {
                let policy = VerifyPolicy {
                    argon2: Some(Argon2Limits {
                        m_cost: 1024,
                        t_cost: 8,
                        p_cost: 4,
                    }),
                    ..VerifyPolicy::new()
                };

                assert_eq!(
                    verify_password_with_policy(PASSWORD, EXAMPLE_HASH, &policy),
                    Err(VerifyError::ParamsExceedLimit)
                );
            }

            #[test]
            fn huge_attacker_controlled_params_never_reach_argon2() {
                // 4 GiB memory request: must be rejected by policy without allocating.
                let hash = "$argon2id$v=19$m=4194304,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo";

                assert_eq!(
                    verify_password_with_policy(PASSWORD, hash, &VerifyPolicy::new()),
                    Err(VerifyError::ParamsExceedLimit)
                );
            }
        }

        #[cfg(feature = "pbkdf2")]
        mod pbkdf2 {
            use super::verify_password_with_policy;
            use crate::{HashAlgorithm, Pbkdf2Limits, VerifyError, VerifyPolicy};

            /// PBKDF2 password test vector from the `pbkdf2` crate.
            const EXAMPLE_PASSWORD: &[u8] = b"passwordPASSWORDpassword";

            const EXAMPLE_HASH: &str = "$pbkdf2-sha256$i=4096,l=40\
                $c2FsdFNBTFRzYWx0U0FMVHNhbHRTQUxUc2FsdFNBTFRzYWx0\
                $NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q";

            #[test]
            fn verifies_and_reports_algorithm() {
                let outcome = verify_password_with_policy(
                    EXAMPLE_PASSWORD,
                    EXAMPLE_HASH,
                    &VerifyPolicy::new(),
                )
                .unwrap();

                assert_eq!(outcome.algorithm, HashAlgorithm::Pbkdf2);
                assert!(outcome.rehash_required);
            }

            #[test]
            fn disabled_algorithm_is_rejected() {
                let policy = VerifyPolicy {
                    pbkdf2: None,
                    ..VerifyPolicy::new()
                };

                assert_eq!(
                    verify_password_with_policy(EXAMPLE_PASSWORD, EXAMPLE_HASH, &policy),
                    Err(VerifyError::AlgorithmDisabled)
                );
            }

            #[test]
            fn too_many_rounds_are_rejected_without_computation() {
                let policy = VerifyPolicy {
                    pbkdf2: Some(Pbkdf2Limits { rounds: 1024 }),
                    ..VerifyPolicy::new()
                };

                assert_eq!(
                    verify_password_with_policy(EXAMPLE_PASSWORD, EXAMPLE_HASH, &policy),
                    Err(VerifyError::ParamsExceedLimit)
                );
            }
        }

        #[cfg(feature = "scrypt")]
        mod scrypt {
            use super::{PASSWORD, verify_password_with_policy};
            use crate::{HashAlgorithm, ScryptLimits, VerifyError, VerifyPolicy};

            /// scrypt hash for the string "password".
            const EXAMPLE_HASH: &str = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

            #[test]
            fn verifies_and_reports_algorithm() {
                let outcome =
                    verify_password_with_policy(PASSWORD, EXAMPLE_HASH, &VerifyPolicy::new())
                        .unwrap();

                assert_eq!(outcome.algorithm, HashAlgorithm::Scrypt);
                assert!(outcome.rehash_required);
            }

            #[test]
            fn disabled_algorithm_is_rejected() {
                let policy = VerifyPolicy {
                    scrypt: None,
                    ..VerifyPolicy::new()
                };

                assert_eq!(
                    verify_password_with_policy(PASSWORD, EXAMPLE_HASH, &policy),
                    Err(VerifyError::AlgorithmDisabled)
                );
            }

            #[test]
            fn oversized_log_n_is_rejected_without_computation() {
                let policy = VerifyPolicy {
                    scrypt: Some(ScryptLimits {
                        log_n: 15,
                        r: 16,
                        p: 4,
                    }),
                    ..VerifyPolicy::new()
                };

                assert_eq!(
                    verify_password_with_policy(PASSWORD, EXAMPLE_HASH, &policy),
                    Err(VerifyError::ParamsExceedLimit)
                );
            }

            #[test]
            fn huge_attacker_controlled_params_never_reach_scrypt() {
                // ln=30 parses successfully but would need ~128 GiB; the policy must stop it.
                let hash = "$scrypt$ln=30,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

                assert_eq!(
                    verify_password_with_policy(PASSWORD, hash, &VerifyPolicy::new()),
                    Err(VerifyError::ParamsExceedLimit)
                );
            }
        }
    }
}
