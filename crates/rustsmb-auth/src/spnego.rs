//! SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism) implementation.
//!
//! SPNEGO is used to negotiate authentication mechanisms and wrap tokens.
//! SMB2 uses SPNEGO for SESSION_SETUP authentication.
//!
//! # Token Flow
//!
//! 1. Client sends NegTokenInit with supported mechanisms
//! 2. Server responds with NegTokenResp (challenge or accept)
//! 3. Client sends NegTokenResp with response
//! 4. Server sends final NegTokenResp (accept/reject)

use crate::{
    AuthContext, AuthMechanism, AuthProvider, AuthResult, BoxFuture, DynAuthProvider, UserInfo,
};
use rustsmb_core::AuthError;
use tracing::{debug, trace, warn};

/// SPNEGO OIDs.
pub mod oid {
    /// SPNEGO mechanism OID: 1.3.6.1.5.5.2
    pub const SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

    /// NTLM mechanism OID: 1.3.6.1.4.1.311.2.2.10
    pub const NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

    /// MS-KRB5 (Microsoft Kerberos 5) OID: 1.2.840.48018.1.2.2
    pub const MS_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];

    /// KRB5 (Kerberos 5) OID: 1.2.840.113554.1.2.2
    pub const KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
}

/// SPNEGO negotiation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegState {
    /// Negotiation complete, accept.
    AcceptCompleted = 0,
    /// Negotiation in progress.
    AcceptIncomplete = 1,
    /// Negotiation rejected.
    Reject = 2,
    /// Request MIC.
    RequestMic = 3,
}

impl TryFrom<u8> for NegState {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AcceptCompleted),
            1 => Ok(Self::AcceptIncomplete),
            2 => Ok(Self::Reject),
            3 => Ok(Self::RequestMic),
            _ => Err(()),
        }
    }
}

/// Parsed NegTokenInit.
#[derive(Debug, Default)]
pub struct NegTokenInit {
    /// Supported mechanism types (OIDs).
    pub mech_types: Vec<Vec<u8>>,
    /// Context flags.
    pub req_flags: Option<u32>,
    /// Mechanism token.
    pub mech_token: Option<Vec<u8>>,
    /// Mechanism list MIC.
    pub mech_list_mic: Option<Vec<u8>>,
}

/// Parsed NegTokenResp.
#[derive(Debug, Default)]
pub struct NegTokenResp {
    /// Negotiation state.
    pub neg_state: Option<NegState>,
    /// Supported mechanism.
    pub supported_mech: Option<Vec<u8>>,
    /// Response token.
    pub response_token: Option<Vec<u8>>,
    /// MIC.
    pub mech_list_mic: Option<Vec<u8>>,
}

/// SPNEGO authentication provider.
///
/// Wraps an underlying provider (NTLM, Kerberos) with SPNEGO negotiation.
pub struct SpnegoProvider {
    /// Underlying authentication provider.
    inner: DynAuthProvider,
    /// Mechanism OID for the inner provider.
    mech_oid: Vec<u8>,
}

impl SpnegoProvider {
    /// Create a new SPNEGO provider wrapping NTLM.
    pub fn ntlm(ntlm_provider: DynAuthProvider) -> Self {
        Self {
            inner: ntlm_provider,
            mech_oid: oid::NTLMSSP.to_vec(),
        }
    }

    /// Create with custom mechanism OID.
    pub fn with_mechanism(provider: DynAuthProvider, oid: &[u8]) -> Self {
        Self {
            inner: provider,
            mech_oid: oid.to_vec(),
        }
    }

    /// Process NegTokenInit (initial client message).
    async fn process_init(
        &self,
        context: &mut AuthContext,
        init: &NegTokenInit,
    ) -> Result<AuthResult, AuthError> {
        debug!(
            "Processing SPNEGO NegTokenInit with {} mechanisms",
            init.mech_types.len()
        );

        // Check if our mechanism is supported
        let supported = init.mech_types.iter().any(|m| m == &self.mech_oid);
        if !supported {
            warn!("Client doesn't support our mechanism");
            return Ok(AuthResult::Failure {
                reason: AuthError::UnsupportedMechanism("No common mechanism".to_string()),
            });
        }

        // If there's a mechanism token, process it
        if let Some(ref token) = init.mech_token {
            let result = self.inner.authenticate(context, token).await?;

            match result {
                AuthResult::Continue { response_token } => {
                    // Wrap in NegTokenResp
                    let resp = build_neg_token_resp(
                        Some(NegState::AcceptIncomplete),
                        Some(&self.mech_oid),
                        Some(&response_token),
                        None,
                    );
                    Ok(AuthResult::Continue {
                        response_token: resp,
                    })
                }
                AuthResult::Success {
                    user: _,
                    session_key: _,
                } => {
                    let resp = build_neg_token_resp(
                        Some(NegState::AcceptCompleted),
                        Some(&self.mech_oid),
                        None,
                        None,
                    );
                    // Return success with wrapped token
                    Ok(AuthResult::Continue {
                        response_token: resp,
                    })
                    // Note: In real impl, we'd track state and return Success on next call
                }
                AuthResult::Failure { reason } => {
                    let _resp = build_neg_token_resp(Some(NegState::Reject), None, None, None);
                    Ok(AuthResult::Failure { reason })
                }
            }
        } else {
            // No token, send initial challenge
            // Create empty token to trigger challenge generation
            let result = self.inner.authenticate(context, &[]).await;

            match result {
                Ok(AuthResult::Continue { response_token }) => {
                    let resp = build_neg_token_resp(
                        Some(NegState::AcceptIncomplete),
                        Some(&self.mech_oid),
                        Some(&response_token),
                        None,
                    );
                    Ok(AuthResult::Continue {
                        response_token: resp,
                    })
                }
                Ok(other) => Ok(other),
                Err(e) => Err(e),
            }
        }
    }

    /// Process NegTokenResp (subsequent messages).
    async fn process_resp(
        &self,
        context: &mut AuthContext,
        resp: &NegTokenResp,
    ) -> Result<AuthResult, AuthError> {
        debug!("Processing SPNEGO NegTokenResp");

        // Get the response token
        let token = resp
            .response_token
            .as_ref()
            .ok_or(AuthError::Failed("No response token".to_string()))?;

        let result = self.inner.authenticate(context, token).await?;

        match result {
            AuthResult::Continue { response_token } => {
                let resp = build_neg_token_resp(
                    Some(NegState::AcceptIncomplete),
                    None,
                    Some(&response_token),
                    None,
                );
                Ok(AuthResult::Continue {
                    response_token: resp,
                })
            }
            AuthResult::Success { user, session_key } => {
                let _resp = build_neg_token_resp(Some(NegState::AcceptCompleted), None, None, None);
                Ok(AuthResult::Success { user, session_key })
            }
            AuthResult::Failure { reason } => {
                let _resp = build_neg_token_resp(Some(NegState::Reject), None, None, None);
                Ok(AuthResult::Failure { reason })
            }
        }
    }
}

impl AuthProvider for SpnegoProvider {
    fn authenticate<'a>(
        &'a self,
        context: &'a mut AuthContext,
        token: &'a [u8],
    ) -> BoxFuture<'a, Result<AuthResult, AuthError>> {
        Box::pin(async move {
            trace!("SPNEGO authenticate, token len: {}", token.len());

            // Try to parse as SPNEGO token
            if let Some(init) = parse_neg_token_init(token) {
                return self.process_init(context, &init).await;
            }

            if let Some(resp) = parse_neg_token_resp(token) {
                return self.process_resp(context, &resp).await;
            }

            // If not SPNEGO, try raw NTLM (some clients skip SPNEGO)
            debug!("Token is not SPNEGO, trying raw mechanism");
            let result = self.inner.authenticate(context, token).await?;

            // Wrap response if needed
            match result {
                AuthResult::Continue { response_token } => {
                    // Wrap in SPNEGO only if it's not already
                    if response_token.len() >= 2 && response_token[0] == 0xa1 {
                        Ok(AuthResult::Continue { response_token })
                    } else {
                        let resp = build_neg_token_resp(
                            Some(NegState::AcceptIncomplete),
                            Some(&self.mech_oid),
                            Some(&response_token),
                            None,
                        );
                        Ok(AuthResult::Continue {
                            response_token: resp,
                        })
                    }
                }
                other => Ok(other),
            }
        })
    }

    fn get_user<'a>(
        &'a self,
        username: &'a str,
        domain: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<UserInfo>, AuthError>> {
        self.inner.get_user(username, domain)
    }

    fn validate_session_key<'a>(
        &'a self,
        session_id: u64,
        key: &'a [u8],
    ) -> BoxFuture<'a, Result<bool, AuthError>> {
        self.inner.validate_session_key(session_id, key)
    }

    fn supported_mechanisms(&self) -> Vec<AuthMechanism> {
        self.inner.supported_mechanisms()
    }
}

/// Parse NegTokenInit from ASN.1/DER.
pub fn parse_neg_token_init(data: &[u8]) -> Option<NegTokenInit> {
    // Check for application tag [0] (NegTokenInit)
    if data.len() < 4 {
        return None;
    }

    // Could be wrapped in GSSAPI header (0x60) or direct (0xa0)
    let mut offset = 0;

    // Skip GSSAPI header if present
    if data[0] == 0x60 {
        let (_, gss_len) = parse_der_length(&data[1..])?;
        offset = 1 + length_size(gss_len);

        // Skip OID
        if data.get(offset)? != &0x06 {
            return None;
        }
        let (_, oid_len) = parse_der_length(&data[offset + 1..])?;
        offset += 1 + length_size(oid_len) + oid_len;
    }

    // Now should be at NegTokenInit (0xa0)
    if data.get(offset)? != &0xa0 {
        return None;
    }

    let (_, init_len) = parse_der_length(&data[offset + 1..])?;
    offset += 1 + length_size(init_len);

    // Parse SEQUENCE
    if data.get(offset)? != &0x30 {
        return None;
    }
    let (_, seq_len) = parse_der_length(&data[offset + 1..])?;
    offset += 1 + length_size(seq_len);

    let mut init = NegTokenInit::default();

    // Parse fields by context tag
    while offset < data.len() {
        let tag = *data.get(offset)?;
        let (_, field_len) = parse_der_length(&data[offset + 1..])?;
        let field_offset = offset + 1 + length_size(field_len);
        let field_end = field_offset + field_len;

        match tag {
            0xa0 => {
                // mechTypes - SEQUENCE OF OID
                init.mech_types = parse_mech_types(&data[field_offset..field_end])?;
            }
            0xa1 => {
                // reqFlags - BIT STRING
                // Skip for now
            }
            0xa2 => {
                // mechToken - OCTET STRING
                if data.get(field_offset)? == &0x04 {
                    let (_, token_len) = parse_der_length(&data[field_offset + 1..])?;
                    let token_start = field_offset + 1 + length_size(token_len);
                    init.mech_token = Some(data[token_start..token_start + token_len].to_vec());
                }
            }
            0xa3 => {
                // mechListMIC - OCTET STRING
            }
            _ => {}
        }

        offset = field_end;
    }

    Some(init)
}

/// Parse NegTokenResp from ASN.1/DER.
pub fn parse_neg_token_resp(data: &[u8]) -> Option<NegTokenResp> {
    if data.len() < 2 {
        return None;
    }

    // NegTokenResp starts with [1] (0xa1)
    if data[0] != 0xa1 {
        return None;
    }

    let (_, resp_len) = parse_der_length(&data[1..])?;
    let mut offset = 1 + length_size(resp_len);

    // SEQUENCE
    if data.get(offset)? != &0x30 {
        return None;
    }
    let (_, seq_len) = parse_der_length(&data[offset + 1..])?;
    offset += 1 + length_size(seq_len);

    let mut resp = NegTokenResp::default();

    while offset < data.len() {
        let tag = *data.get(offset)?;
        let (_, field_len) = parse_der_length(&data[offset + 1..])?;
        let field_offset = offset + 1 + length_size(field_len);
        let field_end = field_offset + field_len;

        match tag {
            0xa0 => {
                // negState - ENUMERATED
                if data.get(field_offset)? == &0x0a {
                    let state = *data.get(field_offset + 2)?;
                    resp.neg_state = NegState::try_from(state).ok();
                }
            }
            0xa1 => {
                // supportedMech - OID
                if data.get(field_offset)? == &0x06 {
                    let (_, oid_len) = parse_der_length(&data[field_offset + 1..])?;
                    let oid_start = field_offset + 1 + length_size(oid_len);
                    resp.supported_mech = Some(data[oid_start..oid_start + oid_len].to_vec());
                }
            }
            0xa2 => {
                // responseToken - OCTET STRING
                if data.get(field_offset)? == &0x04 {
                    let (_, token_len) = parse_der_length(&data[field_offset + 1..])?;
                    let token_start = field_offset + 1 + length_size(token_len);
                    resp.response_token = Some(data[token_start..token_start + token_len].to_vec());
                }
            }
            0xa3 => {
                // mechListMIC
            }
            _ => {}
        }

        offset = field_end;
    }

    Some(resp)
}

/// Build NegTokenResp.
pub fn build_neg_token_resp(
    neg_state: Option<NegState>,
    supported_mech: Option<&[u8]>,
    response_token: Option<&[u8]>,
    mech_list_mic: Option<&[u8]>,
) -> Vec<u8> {
    let mut fields = Vec::new();

    // negState [0] ENUMERATED
    if let Some(state) = neg_state {
        fields.extend_from_slice(&[0xa0, 0x03, 0x0a, 0x01, state as u8]);
    }

    // supportedMech [1] OID
    if let Some(oid) = supported_mech {
        let oid_der = encode_oid(oid);
        fields.push(0xa1);
        fields.extend_from_slice(&encode_der_length(oid_der.len()));
        fields.extend_from_slice(&oid_der);
    }

    // responseToken [2] OCTET STRING
    if let Some(token) = response_token {
        let token_der = encode_octet_string(token);
        fields.push(0xa2);
        fields.extend_from_slice(&encode_der_length(token_der.len()));
        fields.extend_from_slice(&token_der);
    }

    // mechListMIC [3] OCTET STRING
    if let Some(mic) = mech_list_mic {
        let mic_der = encode_octet_string(mic);
        fields.push(0xa3);
        fields.extend_from_slice(&encode_der_length(mic_der.len()));
        fields.extend_from_slice(&mic_der);
    }

    // Wrap in SEQUENCE
    let mut seq = vec![0x30];
    seq.extend_from_slice(&encode_der_length(fields.len()));
    seq.extend_from_slice(&fields);

    // Wrap in [1] (NegTokenResp)
    let mut resp = vec![0xa1];
    resp.extend_from_slice(&encode_der_length(seq.len()));
    resp.extend_from_slice(&seq);

    resp
}

/// Build NegTokenInit for server hints.
pub fn build_neg_token_init(mech_types: &[&[u8]], mech_token: Option<&[u8]>) -> Vec<u8> {
    let mut fields = Vec::new();

    // mechTypes [0] SEQUENCE OF OID
    let mech_seq = encode_mech_types(mech_types);
    fields.push(0xa0);
    fields.extend_from_slice(&encode_der_length(mech_seq.len()));
    fields.extend_from_slice(&mech_seq);

    // mechToken [2] OCTET STRING (optional)
    if let Some(token) = mech_token {
        let token_der = encode_octet_string(token);
        fields.push(0xa2);
        fields.extend_from_slice(&encode_der_length(token_der.len()));
        fields.extend_from_slice(&token_der);
    }

    // Wrap in SEQUENCE
    let mut seq = vec![0x30];
    seq.extend_from_slice(&encode_der_length(fields.len()));
    seq.extend_from_slice(&fields);

    // Wrap in [0] (NegTokenInit)
    let mut init = vec![0xa0];
    init.extend_from_slice(&encode_der_length(seq.len()));
    init.extend_from_slice(&seq);

    // Wrap in GSSAPI header
    let mut gss = vec![0x60];
    let oid_der = encode_oid(oid::SPNEGO);
    let total_len = oid_der.len() + init.len();
    gss.extend_from_slice(&encode_der_length(total_len));
    gss.extend_from_slice(&oid_der);
    gss.extend_from_slice(&init);

    gss
}

// DER encoding helpers

fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    if first < 0x80 {
        return Some((1, first as usize));
    }

    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || data.len() < 1 + num_bytes {
        return None;
    }

    let mut len = 0usize;
    for &b in &data[1..1 + num_bytes] {
        len = len.checked_mul(256)?.checked_add(b as usize)?;
    }

    Some((1 + num_bytes, len))
}

fn length_size(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len < 0x100 {
        2
    } else if len < 0x10000 {
        3
    } else {
        4
    }
}

fn encode_der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

fn encode_oid(oid: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x06];
    buf.extend_from_slice(&encode_der_length(oid.len()));
    buf.extend_from_slice(oid);
    buf
}

fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x04];
    buf.extend_from_slice(&encode_der_length(data.len()));
    buf.extend_from_slice(data);
    buf
}

fn parse_mech_types(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.is_empty() || data[0] != 0x30 {
        return None;
    }

    let (_, seq_len) = parse_der_length(&data[1..])?;
    let mut offset = 1 + length_size(seq_len);
    let end = offset + seq_len;
    let mut types = Vec::new();

    while offset < end && offset < data.len() {
        if data[offset] != 0x06 {
            break;
        }
        let (_, oid_len) = parse_der_length(&data[offset + 1..])?;
        let oid_start = offset + 1 + length_size(oid_len);
        types.push(data[oid_start..oid_start + oid_len].to_vec());
        offset = oid_start + oid_len;
    }

    Some(types)
}

fn encode_mech_types(types: &[&[u8]]) -> Vec<u8> {
    let mut seq_content = Vec::new();
    for oid in types {
        seq_content.extend_from_slice(&encode_oid(oid));
    }

    let mut seq = vec![0x30];
    seq.extend_from_slice(&encode_der_length(seq_content.len()));
    seq.extend_from_slice(&seq_content);
    seq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_parse_neg_token_resp() {
        let token = build_neg_token_resp(
            Some(NegState::AcceptIncomplete),
            Some(oid::NTLMSSP),
            Some(b"test_token"),
            None,
        );

        let parsed = parse_neg_token_resp(&token).unwrap();
        assert_eq!(parsed.neg_state, Some(NegState::AcceptIncomplete));
        assert_eq!(parsed.supported_mech, Some(oid::NTLMSSP.to_vec()));
        assert_eq!(parsed.response_token, Some(b"test_token".to_vec()));
    }

    #[test]
    fn test_build_neg_token_init() {
        let token = build_neg_token_init(&[oid::NTLMSSP], Some(b"test_token"));

        // Should be valid GSSAPI/SPNEGO
        assert_eq!(token[0], 0x60);

        let parsed = parse_neg_token_init(&token).unwrap();
        assert_eq!(parsed.mech_types.len(), 1);
        assert_eq!(parsed.mech_types[0], oid::NTLMSSP);
        assert_eq!(parsed.mech_token, Some(b"test_token".to_vec()));
    }

    #[test]
    fn test_neg_state() {
        assert_eq!(NegState::try_from(0), Ok(NegState::AcceptCompleted));
        assert_eq!(NegState::try_from(1), Ok(NegState::AcceptIncomplete));
        assert_eq!(NegState::try_from(2), Ok(NegState::Reject));
        assert!(NegState::try_from(4).is_err());
    }

    #[test]
    fn test_der_length_encoding() {
        // Short form
        assert_eq!(encode_der_length(0), vec![0]);
        assert_eq!(encode_der_length(127), vec![127]);

        // Long form
        assert_eq!(encode_der_length(128), vec![0x81, 128]);
        assert_eq!(encode_der_length(256), vec![0x82, 1, 0]);
    }
}
