//! Authentication providers for RustSMB.
//!
//! This crate provides the AuthProvider trait and implementations
//! for NTLM, SPNEGO, and simple password authentication.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                   SPNEGO Provider                        │
//! │  (GSS-API negotiation, mechanism selection)             │
//! ├─────────────────────────────────────────────────────────┤
//! │                   NTLM Provider                          │
//! │  (NTLMv2 challenge-response, session keys)              │
//! ├─────────────────────────────────────────────────────────┤
//! │                   Simple Provider                        │
//! │  (Username/password, for testing)                       │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Session Key Derivation
//!
//! SMB 3.0 uses KDF (Key Derivation Function) to derive signing
//! and encryption keys from the session key:
//!
//! - SigningKey = KDF(SessionKey, "SMB2AESCMAC", "SmbSign")
//! - EncryptionKey = KDF(SessionKey, "SMB2AESCCM", "ServerIn")
//! - DecryptionKey = KDF(SessionKey, "SMB2AESCCM", "ServerOut")
//!
//! SMB 3.1.1 adds pre-authentication integrity hashing to bind
//! the session key to the negotiation transcript.

pub mod kdf;
pub mod ntlm;
pub mod preauth;
pub mod provider;
pub mod simple;
pub mod spnego;

pub use kdf::{contexts, labels, sp800_108_kdf, KeyDerivationContext, SessionKeys, SmbDialect};
pub use ntlm::{
    build_target_info, compute_lmv2_response, compute_ntlmv2_response, current_filetime,
    generate_challenge, nt_hash, ntowf_v2, parse_target_info, verify_ntlmv2_response,
    AuthenticateMessage, AvId, AvPair, ChallengeMessage, NegotiateMessage, NtlmAuthProvider,
    NtlmFlags, NtlmMessageType, NtlmVersion, NTLM_SIGNATURE,
};
pub use preauth::{
    build_preauth_integrity_caps, generate_preauth_salt, parse_preauth_integrity_caps,
    ConnectionPreauthContext, PreauthHashAlgorithm, PreauthIntegrityHash, SessionPreauthContext,
    PREAUTH_HASH_SIZE,
};
pub use provider::{
    AnonymousAuthProvider, AuthContext, AuthMechanism, AuthProvider, AuthResult, AuthState,
    BoxFuture, CompositeAuthProvider, DynAuthProvider, SessionType, UserInfo,
};
pub use simple::SimpleAuthProvider;
pub use spnego::{
    build_neg_token_init, build_neg_token_resp, oid, parse_neg_token_init, parse_neg_token_resp,
    NegState, NegTokenInit, NegTokenResp, SpnegoProvider,
};
