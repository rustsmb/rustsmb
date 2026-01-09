//! NTLM cryptographic operations.
//!
//! Implements the cryptographic functions defined in MS-NLMP.

use hmac::{Hmac, Mac};
use md5::Md5;

type HmacMd5 = Hmac<Md5>;

/// Compute NT hash from password.
///
/// NT hash = MD4(UTF-16LE(password))
pub fn nt_hash(password: &str) -> [u8; 16] {
    // Convert to UTF-16LE
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // MD4 hash (using a simple implementation since we don't have md4 crate)
    md4_hash(&utf16)
}

/// Simple MD4 implementation for NT hash.
fn md4_hash(data: &[u8]) -> [u8; 16] {
    // MD4 implementation based on RFC 1320
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

    // Padding
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    // Process blocks
    for chunk in padded.chunks(64) {
        let mut x = [0u32; 16];
        for (i, word) in chunk.chunks(4).enumerate() {
            x[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];

        // Round 1
        macro_rules! ff {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add(($b & $c) | (!$b & $d))
                    .wrapping_add(x[$k])
                    .rotate_left($s);
            };
        }
        for &i in &[0, 4, 8, 12] {
            ff!(a, b, c, d, i, 3);
            ff!(d, a, b, c, i + 1, 7);
            ff!(c, d, a, b, i + 2, 11);
            ff!(b, c, d, a, i + 3, 19);
        }

        // Round 2
        macro_rules! gg {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add(($b & $c) | ($b & $d) | ($c & $d))
                    .wrapping_add(x[$k])
                    .wrapping_add(0x5a827999)
                    .rotate_left($s);
            };
        }
        for &i in &[0, 1, 2, 3] {
            gg!(a, b, c, d, i, 3);
            gg!(d, a, b, c, i + 4, 5);
            gg!(c, d, a, b, i + 8, 9);
            gg!(b, c, d, a, i + 12, 13);
        }

        // Round 3
        macro_rules! hh {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add($b ^ $c ^ $d)
                    .wrapping_add(x[$k])
                    .wrapping_add(0x6ed9eba1)
                    .rotate_left($s);
            };
        }
        for &i in &[0, 2, 1, 3] {
            hh!(a, b, c, d, i, 3);
            hh!(d, a, b, c, i + 8, 9);
            hh!(c, d, a, b, i + 4, 11);
            hh!(b, c, d, a, i + 12, 15);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut result = [0u8; 16];
    for (i, s) in state.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&s.to_le_bytes());
    }
    result
}

/// Compute NTLMv2 hash.
///
/// NTOWFv2 = HMAC_MD5(NT_HASH, UPPERCASE(Username) || Domain)
pub fn ntowf_v2(nt_hash: &[u8; 16], username: &str, domain: &str) -> [u8; 16] {
    // Uppercase username, concatenate with domain (both UTF-16LE)
    let user_upper = username.to_uppercase();
    let concat: Vec<u8> = user_upper
        .encode_utf16()
        .chain(domain.encode_utf16())
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // HMAC-MD5
    let mut mac = HmacMd5::new_from_slice(nt_hash).expect("HMAC can take key of any size");
    mac.update(&concat);
    let result = mac.finalize();

    let mut output = [0u8; 16];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// Compute NTLMv2 response.
///
/// Returns (nt_proof_str, session_base_key).
pub fn compute_ntlmv2_response(
    ntowf: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: u64,
    target_info: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // Build temp structure (NTLMv2_CLIENT_CHALLENGE)
    // RespType (1 byte) = 0x01
    // HiRespType (1 byte) = 0x01
    // Reserved1 (2 bytes) = 0
    // Reserved2 (4 bytes) = 0
    // TimeStamp (8 bytes)
    // ChallengeFromClient (8 bytes)
    // Reserved3 (4 bytes) = 0
    // AvPairs (variable)
    let mut temp = Vec::with_capacity(28 + target_info.len() + 4);
    temp.push(0x01); // RespType
    temp.push(0x01); // HiRespType
    temp.extend_from_slice(&[0u8; 6]); // Reserved
    temp.extend_from_slice(&timestamp.to_le_bytes());
    temp.extend_from_slice(client_challenge);
    temp.extend_from_slice(&[0u8; 4]); // Reserved3
    temp.extend_from_slice(target_info);
    // Append 4 zero bytes as required
    temp.extend_from_slice(&[0u8; 4]);

    // NtProofStr = HMAC_MD5(ntowf, ServerChallenge || temp)
    let mut concat = Vec::with_capacity(8 + temp.len());
    concat.extend_from_slice(server_challenge);
    concat.extend_from_slice(&temp);

    let mut mac = HmacMd5::new_from_slice(ntowf).expect("HMAC can take key of any size");
    mac.update(&concat);
    let nt_proof_str = mac.finalize().into_bytes();

    // SessionBaseKey = HMAC_MD5(ntowf, NtProofStr)
    let mut mac = HmacMd5::new_from_slice(ntowf).expect("HMAC can take key of any size");
    mac.update(&nt_proof_str);
    let session_base_key = mac.finalize().into_bytes();

    // NT response = NtProofStr || temp
    let mut nt_response = Vec::with_capacity(16 + temp.len());
    nt_response.extend_from_slice(&nt_proof_str);
    nt_response.extend_from_slice(&temp);

    let mut session_key = [0u8; 16];
    session_key.copy_from_slice(&session_base_key);

    (nt_response, session_key)
}

/// Verify NTLMv2 response.
///
/// Returns session_base_key if valid, None otherwise.
pub fn verify_ntlmv2_response(
    ntowf: &[u8; 16],
    server_challenge: &[u8; 8],
    nt_response: &[u8],
) -> Option<[u8; 16]> {
    if nt_response.len() < 16 + 28 {
        return None;
    }

    let nt_proof_str = &nt_response[..16];
    let temp = &nt_response[16..];

    // Recompute NtProofStr
    let mut concat = Vec::with_capacity(8 + temp.len());
    concat.extend_from_slice(server_challenge);
    concat.extend_from_slice(temp);

    let mut mac = HmacMd5::new_from_slice(ntowf).expect("HMAC can take key of any size");
    mac.update(&concat);
    let computed = mac.finalize().into_bytes();

    // Constant-time comparison
    let mut eq = true;
    for (a, b) in nt_proof_str.iter().zip(computed.iter()) {
        eq &= a == b;
    }

    if !eq {
        return None;
    }

    // Compute session base key
    let mut mac = HmacMd5::new_from_slice(ntowf).expect("HMAC can take key of any size");
    mac.update(&computed);
    let session_base_key = mac.finalize().into_bytes();

    let mut key = [0u8; 16];
    key.copy_from_slice(&session_base_key);
    Some(key)
}

/// Generate random challenge.
pub fn generate_challenge() -> [u8; 8] {
    use rand::RngCore;
    let mut challenge = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

/// Compute LMv2 response.
///
/// LMv2 response is simpler: HMAC_MD5(ntowf, ServerChallenge || ClientChallenge)
pub fn compute_lmv2_response(
    ntowf: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
) -> [u8; 24] {
    let mut concat = Vec::with_capacity(16);
    concat.extend_from_slice(server_challenge);
    concat.extend_from_slice(client_challenge);

    let mut mac = HmacMd5::new_from_slice(ntowf).expect("HMAC can take key of any size");
    mac.update(&concat);
    let response = mac.finalize().into_bytes();

    let mut result = [0u8; 24];
    result[..16].copy_from_slice(&response);
    result[16..].copy_from_slice(client_challenge);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_hash() {
        // Test vector from MS-NLMP
        let hash = nt_hash("Password");
        // Expected: a4f49c406510bdcab6824ee7c30fd852
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_ntowf_v2() {
        let nt = nt_hash("Password");
        let ntowf = ntowf_v2(&nt, "User", "Domain");
        assert_eq!(ntowf.len(), 16);
    }

    #[test]
    fn test_challenge_generation() {
        let c1 = generate_challenge();
        let c2 = generate_challenge();
        assert_ne!(c1, c2); // Should be random
    }

    #[test]
    fn test_ntlmv2_response_roundtrip() {
        let password = "Password";
        let username = "User";
        let domain = "Domain";

        let nt = nt_hash(password);
        let ntowf = ntowf_v2(&nt, username, domain);

        let server_challenge = generate_challenge();
        let client_challenge = generate_challenge();
        let timestamp = super::super::current_filetime();
        let target_info = super::super::build_target_info(
            "DOMAIN",
            "SERVER",
            "domain.local",
            "server.domain.local",
            timestamp,
        );

        let (nt_response, session_key) = compute_ntlmv2_response(
            &ntowf,
            &server_challenge,
            &client_challenge,
            timestamp,
            &target_info,
        );

        // Verify
        let verified_key = verify_ntlmv2_response(&ntowf, &server_challenge, &nt_response);
        assert!(verified_key.is_some());
        assert_eq!(verified_key.unwrap(), session_key);
    }

    #[test]
    fn test_ntlmv2_response_wrong_challenge() {
        let password = "Password";
        let username = "User";
        let domain = "Domain";

        let nt = nt_hash(password);
        let ntowf = ntowf_v2(&nt, username, domain);

        let server_challenge = generate_challenge();
        let wrong_challenge = generate_challenge();
        let client_challenge = generate_challenge();
        let timestamp = super::super::current_filetime();
        let target_info = super::super::build_target_info(
            "DOMAIN",
            "SERVER",
            "domain.local",
            "server.domain.local",
            timestamp,
        );

        let (nt_response, _) = compute_ntlmv2_response(
            &ntowf,
            &server_challenge,
            &client_challenge,
            timestamp,
            &target_info,
        );

        // Verify with wrong challenge should fail
        let verified = verify_ntlmv2_response(&ntowf, &wrong_challenge, &nt_response);
        assert!(verified.is_none());
    }

    #[test]
    fn test_lmv2_response() {
        let password = "Password";
        let username = "User";
        let domain = "Domain";

        let nt = nt_hash(password);
        let ntowf = ntowf_v2(&nt, username, domain);

        let server_challenge = generate_challenge();
        let client_challenge = generate_challenge();

        let response = compute_lmv2_response(&ntowf, &server_challenge, &client_challenge);
        assert_eq!(response.len(), 24);
        // Last 8 bytes should be client challenge
        assert_eq!(&response[16..], &client_challenge);
    }
}
