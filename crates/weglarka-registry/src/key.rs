//! Strict parsing of a PEM/DER SubjectPublicKeyInfo public key.
//!
//! The daemon pins one key (`cosign.pub` in the repository root, [`crate::DEFAULT_PUBLIC_KEY_PEM`])
//! and uses it to verify self-update signatures. The parser therefore accepts exactly one shape —
//! an ECDSA P-256 key in an uncompressed point — and every other input gets a specific error
//! instead of being coerced: RSA, Ed25519, P-384, a certificate, garbage base64, trailing data,
//! non-minimal DER lengths. Signature verification itself is done by `ring`; this module only makes
//! sure `ring` never sees a key the operator did not intend to pin.

use ring::signature::UnparsedPublicKey;

/// DER of the `id-ecPublicKey` algorithm OID (1.2.840.10045.2.1).
const EC_PUBLIC_KEY_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// DER of the `prime256v1` / P-256 curve OID (1.2.840.10045.3.1.7).
const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// PEM input limit: a P-256 SPKI is ~120 bytes of base64; anything bigger is not our key.
const MAX_PEM_LEN: usize = 16 * 1024;
/// DER input limit.
const MAX_DER_LEN: usize = 4 * 1024;

/// A pinned ECDSA P-256 public key, parsed from PEM or DER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// The 65-byte SEC1 uncompressed point (`0x04 || x || y`).
    point: [u8; 65],
}

impl PublicKey {
    /// Parses a PEM `PUBLIC KEY` block (SubjectPublicKeyInfo). Exactly one block and nothing else.
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        if pem.len() > MAX_PEM_LEN {
            return Err(KeyError::TooLong(pem.len(), MAX_PEM_LEN));
        }
        let der = decode_pem(pem)?;
        Self::from_der(&der)
    }

    /// Parses a DER SubjectPublicKeyInfo.
    pub fn from_der(der: &[u8]) -> Result<Self, KeyError> {
        if der.len() > MAX_DER_LEN {
            return Err(KeyError::TooLong(der.len(), MAX_DER_LEN));
        }
        let mut top = Der::new(der);
        let (tag, spki) = top.read()?;
        if tag != TAG_SEQUENCE {
            return Err(KeyError::Der("the public key is not a SEQUENCE"));
        }
        if !top.is_empty() {
            return Err(KeyError::TrailingData);
        }
        let mut spki = Der::new(spki);
        let (tag, algorithm) = spki.read()?;
        if tag != TAG_SEQUENCE {
            return Err(KeyError::Der("the algorithm identifier is not a SEQUENCE"));
        }
        let mut algorithm = Der::new(algorithm);
        let (tag, oid) = algorithm.read()?;
        if tag != TAG_OID {
            return Err(KeyError::Der("the algorithm OID is missing"));
        }
        if oid != EC_PUBLIC_KEY_OID {
            return Err(KeyError::UnsupportedAlgorithm(oid_to_string(oid)));
        }
        let (tag, curve) = algorithm.read()?;
        if tag != TAG_OID {
            return Err(KeyError::Der("the named curve OID is missing"));
        }
        if curve != P256_OID {
            return Err(KeyError::UnsupportedCurve(oid_to_string(curve)));
        }
        if !algorithm.is_empty() {
            return Err(KeyError::Der("unexpected data in the algorithm identifier"));
        }
        let (tag, bits) = spki.read()?;
        if tag != TAG_BIT_STRING {
            return Err(KeyError::Der("the public key is not a BIT STRING"));
        }
        let point = match bits.split_first() {
            // The first byte counts the unused bits of the last octet; a key is octet-aligned.
            Some((0, point)) => point,
            Some(_) => return Err(KeyError::Der("the BIT STRING does not start on an octet")),
            None => return Err(KeyError::Point),
        };
        let point: [u8; 65] = point.try_into().map_err(|_| KeyError::Point)?;
        if point[0] != 0x04 {
            return Err(KeyError::Point);
        }
        if !spki.is_empty() {
            return Err(KeyError::Der("unexpected data in the public key"));
        }
        Ok(Self { point })
    }

    /// Verifies an ASN.1 DER ECDSA P-256 / SHA-256 signature over `payload`.
    ///
    /// The payload is hashed by `ring`; the signature must be DER, as cosign writes it.
    pub(crate) fn verify(&self, payload: &[u8], signature: &[u8]) -> bool {
        let key = UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            self.point.as_slice(),
        );
        key.verify(payload, signature).is_ok()
    }

    /// The SEC1 uncompressed point; exposed for tests that build a key from scratch.
    #[cfg(test)]
    pub(crate) fn point(&self) -> &[u8; 65] {
        &self.point
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("the public key is not a PEM 'PUBLIC KEY' block")]
    NotPem,
    #[error("the public key is {0} bytes, the limit is {1}")]
    TooLong(usize, usize),
    #[error("unsupported PEM label {0:?}: expected \"PUBLIC KEY\"")]
    WrongLabel(String),
    #[error("malformed PEM: {0}")]
    Pem(&'static str),
    #[error("the PEM body is not valid base64: {0}")]
    Base64(String),
    #[error("the public key is not valid DER: {0}")]
    Der(&'static str),
    #[error("unsupported public key algorithm {0:?}: only ECDSA P-256 is accepted")]
    UnsupportedAlgorithm(String),
    #[error("unsupported elliptic curve {0:?}: only P-256 (prime256v1) is accepted")]
    UnsupportedCurve(String),
    #[error("the public key is not an uncompressed 65-byte P-256 point")]
    Point,
    #[error("data after the public key")]
    TrailingData,
}

const BEGIN: &str = "-----BEGIN ";
const END: &str = "-----END ";
const DASHES: &str = "-----";
const PUBLIC_KEY_LABEL: &str = "PUBLIC KEY";

/// Decodes a single strict PEM block. CRLF line endings are accepted (a file checked out on
/// Windows), blank lines inside the block are not.
fn decode_pem(pem: &str) -> Result<Vec<u8>, KeyError> {
    use base64::Engine as _;

    let trimmed = pem.trim_end_matches(['\n', '\r', ' ', '\t']);
    let lines: Vec<&str> = trimmed
        .split('\n')
        .map(|line| line.trim_end_matches('\r'))
        .collect();
    let begin = *lines.first().ok_or(KeyError::NotPem)?;
    let label = begin
        .strip_prefix(BEGIN)
        .and_then(|line| line.strip_suffix(DASHES))
        .ok_or(KeyError::NotPem)?;
    if label != PUBLIC_KEY_LABEL {
        return Err(KeyError::WrongLabel(label.to_owned()));
    }
    let mut body = String::new();
    let mut saw_end = false;
    let mut index = 1;
    while let Some(&line) = lines.get(index) {
        index += 1;
        if let Some(end) = line.strip_prefix(END).and_then(|l| l.strip_suffix(DASHES)) {
            if end != PUBLIC_KEY_LABEL {
                return Err(KeyError::WrongLabel(end.to_owned()));
            }
            saw_end = true;
            break;
        }
        if line.is_empty() {
            return Err(KeyError::Pem("blank line in the key body"));
        }
        if !line.bytes().all(is_base64_byte) {
            return Err(KeyError::Pem("unexpected character in the key body"));
        }
        body.push_str(line);
    }
    if !saw_end {
        return Err(KeyError::Pem("the PEM block is not terminated"));
    }
    // Anything after the END line means the input is not the single key we expected.
    if lines[index..].iter().any(|line| !line.is_empty()) {
        return Err(KeyError::TrailingData);
    }
    if body.is_empty() {
        return Err(KeyError::Pem("the PEM block is empty"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| KeyError::Base64(e.to_string()))
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

const TAG_SEQUENCE: u8 = 0x30;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OID: u8 = 0x06;

/// A strict DER reader: definite lengths only, minimal length encoding, no high-tag-number form,
/// and every value must fit its parent (so truncation is an error, never a short read).
struct Der<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn read(&mut self) -> Result<(u8, &'a [u8]), KeyError> {
        let tag = *self
            .bytes
            .get(self.pos)
            .ok_or(KeyError::Der("truncated DER tag"))?;
        self.pos += 1;
        if tag & 0x1f == 0x1f {
            return Err(KeyError::Der("high-tag-number DER is not supported"));
        }
        let first = *self
            .bytes
            .get(self.pos)
            .ok_or(KeyError::Der("truncated DER length"))?;
        self.pos += 1;
        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return Err(KeyError::Der("unsupported DER length encoding"));
            }
            let encoded = self
                .bytes
                .get(self.pos..self.pos + count)
                .ok_or(KeyError::Der("truncated DER length"))?;
            if encoded[0] == 0 {
                return Err(KeyError::Der("non-minimal DER length"));
            }
            self.pos += count;
            let mut length = 0usize;
            for byte in encoded {
                length = length
                    .checked_mul(256)
                    .and_then(|length| length.checked_add(usize::from(*byte)))
                    .ok_or(KeyError::Der("DER length overflow"))?;
            }
            let minimal = if length < 0x100 {
                1
            } else if length < 0x1_0000 {
                2
            } else if length < 0x100_0000 {
                3
            } else {
                4
            };
            // A value below 128 must use the short form; anything else must use exactly as many
            // length bytes as needed (a leading zero or an extra byte is a non-canonical encoding).
            if length < 0x80 || count != minimal {
                return Err(KeyError::Der("non-minimal DER length"));
            }
            length
        };
        let end = self
            .pos
            .checked_add(length)
            .ok_or(KeyError::Der("DER length overflow"))?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or(KeyError::Der("truncated DER value"))?;
        self.pos = end;
        Ok((tag, value))
    }
}

/// Renders an OID for error messages (`1.2.840.10045.3.1.7`); malformed OIDs are rendered as hex.
fn oid_to_string(oid: &[u8]) -> String {
    use std::fmt::Write as _;

    let Some((&first, rest)) = oid.split_first() else {
        return "empty OID".to_owned();
    };
    let mut out = if first < 40 {
        format!("0.{first}")
    } else if first < 80 {
        format!("1.{}", first - 40)
    } else {
        format!("2.{}", first - 80)
    };
    let mut value = 0u64;
    let mut open = false;
    for &byte in rest {
        value = value
            .saturating_mul(128)
            .saturating_add(u64::from(byte & 0x7f));
        open = byte & 0x80 != 0;
        if !open {
            let _ = write!(out, ".{value}");
            value = 0;
        }
    }
    if open {
        return format!("{out}.…");
    }
    out
}

/// A DER SubjectPublicKeyInfo for a P-256 key with an arbitrary point (lengths are computed so
/// that malformed points, not malformed DER, are the thing under test).
#[cfg(any(test, feature = "testing"))]
pub(crate) fn spki_der(point: &[u8]) -> Vec<u8> {
    let mut algorithm = der_tlv(0x06, EC_PUBLIC_KEY_OID);
    algorithm.extend_from_slice(&der_tlv(0x06, P256_OID));
    let mut bits = vec![0x00];
    bits.extend_from_slice(point);
    let mut spki = der_tlv(0x30, &algorithm);
    spki.extend_from_slice(&der_tlv(0x03, &bits));
    der_tlv(0x30, &spki)
}

#[cfg(any(test, feature = "testing"))]
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        0..=0x7f => out.push(content.len() as u8),
        0x80..=0xff => out.extend_from_slice(&[0x81, content.len() as u8]),
        _ => out.extend_from_slice(&[0x82, (content.len() >> 8) as u8, content.len() as u8]),
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real RSA-2048 SPKI (generated locally, public data).
    const RSA_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxOyWYQN8FDDUuZUYPPvF
7HHpc++lsEQUm3vP23E6Y7qZQRKwOqf7/1npvWR4CR7ql1yjMtMMMeYa/2FgPq+L
OBG5ANCv8YddWT84Q4mQcLnQkMFczSGakyliuTAMqPhE/elnLJUvN/JhOgOCGHsC
3tQQLC/NzKkpFrdwzRWgYObLLPih+cCcshX7dbmpo454oW0r0NtRjrXDg9w88xk3
XwLW7/LdGXiho3UPlY4JpciyS6lmSC60F/Mr2C1vr3ZZJDQz03Y8dnQ5UpfYo8Gc
dZquqDAw/VGPCY7JvuTNWDyQTTo1gzDo5qE4PRKwDeNl1Fw/UvsF3avXKYOEuL3k
4QIDAQAB
-----END PUBLIC KEY-----";

    /// A real P-384 SPKI (generated locally, public data).
    const P384_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEagJb3aJasMuq/phnlyoESbDRlvnJz+h4
3XK6Rtl/98BfL2FOdscKvIK2janKMs8yD5alJuofIXOICQo8mOhpNr4V5xTXuWOr
ogGha2MkHhI9xdYbrrRSYFk0bOvHXLFI
-----END PUBLIC KEY-----";

    #[test]
    fn parses_the_pinned_default_key() {
        let key = PublicKey::from_pem(crate::DEFAULT_PUBLIC_KEY_PEM).unwrap();
        assert_eq!(key.point().len(), 65);
        assert_eq!(key.point()[0], 0x04);
        // The default key is P-256 SPKI: 91 bytes of DER, 65 of them the point.
        assert_eq!(
            key,
            PublicKey::from_pem(crate::DEFAULT_PUBLIC_KEY_PEM).unwrap()
        );
    }

    #[test]
    fn accepts_crlf_and_missing_trailing_newline() {
        let crlf = crate::DEFAULT_PUBLIC_KEY_PEM.replace('\n', "\r\n");
        assert!(PublicKey::from_pem(&crlf).is_ok());
        let bare = crate::DEFAULT_PUBLIC_KEY_PEM.trim_end();
        assert!(PublicKey::from_pem(bare).is_ok());
    }

    #[test]
    fn rejects_other_algorithms_and_curves() {
        assert_eq!(
            PublicKey::from_pem(RSA_PUBLIC_KEY_PEM).unwrap_err(),
            KeyError::UnsupportedAlgorithm("1.2.840.113549.1.1.1".into())
        );
        assert_eq!(
            PublicKey::from_pem(P384_PUBLIC_KEY_PEM).unwrap_err(),
            KeyError::UnsupportedCurve("1.3.132.0.34".into())
        );
        // A certificate, not a bare key, is a wrong label.
        let certificate = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        assert_eq!(
            PublicKey::from_pem(certificate).unwrap_err(),
            KeyError::WrongLabel("CERTIFICATE".into())
        );
        // An RSA-key PEM label (PKCS#1) is a wrong label too.
        let rsa_label = "-----BEGIN RSA PUBLIC KEY-----\nMIIB\n-----END RSA PUBLIC KEY-----";
        assert_eq!(
            PublicKey::from_pem(rsa_label).unwrap_err(),
            KeyError::WrongLabel("RSA PUBLIC KEY".into())
        );
    }

    #[test]
    fn rejects_garbage_pem_and_base64() {
        for pem in [
            "",
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
            "-----BEGIN PUBLIC KEY-----\nnot base64!!\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\nMFkw\n\nMFkw\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\nMFkw\n",
        ] {
            let err = PublicKey::from_pem(pem).unwrap_err();
            assert!(
                matches!(
                    err,
                    KeyError::NotPem | KeyError::Pem(_) | KeyError::Base64(_)
                ),
                "{pem:?}: {err}"
            );
        }
        // Valid base64, invalid DER.
        assert_eq!(
            PublicKey::from_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")
                .unwrap_err(),
            KeyError::Der("the public key is not a SEQUENCE")
        );
    }

    #[test]
    fn rejects_trailing_data_after_the_block() {
        let with_extra_block = format!(
            "{}\n-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
            crate::DEFAULT_PUBLIC_KEY_PEM
        );
        assert_eq!(
            PublicKey::from_pem(&with_extra_block).unwrap_err(),
            KeyError::TrailingData
        );
        // Two concatenated keys: the parser stops at the first END and rejects the rest.
        let two = format!(
            "{}{}",
            crate::DEFAULT_PUBLIC_KEY_PEM,
            crate::DEFAULT_PUBLIC_KEY_PEM
        );
        assert_eq!(
            PublicKey::from_pem(&two).unwrap_err(),
            KeyError::TrailingData
        );
    }

    #[test]
    fn der_reader_rejects_non_minimal_and_truncated_encodings() {
        let key = PublicKey::from_pem(crate::DEFAULT_PUBLIC_KEY_PEM).unwrap();
        let minimal = spki_der(key.point());
        assert_eq!(PublicKey::from_der(&minimal).unwrap(), key);

        // Trailing byte after the outer SEQUENCE.
        let mut der = minimal.clone();
        der.push(0);
        assert_eq!(
            PublicKey::from_der(&der).unwrap_err(),
            KeyError::TrailingData
        );

        // Truncated outer SEQUENCE.
        assert!(matches!(
            PublicKey::from_der(&minimal[..minimal.len() - 2]).unwrap_err(),
            KeyError::Der(_)
        ));

        // Non-minimal length: a value below 128 encoded in the long form.
        let mut non_minimal = minimal[..1].to_vec();
        non_minimal.extend_from_slice(&[0x81, 0x59]);
        non_minimal.extend_from_slice(&minimal[2..]);
        assert_eq!(
            PublicKey::from_der(&non_minimal).unwrap_err(),
            KeyError::Der("non-minimal DER length")
        );

        // Indefinite length (0x80) is not DER.
        assert!(matches!(
            PublicKey::from_der(&[0x30, 0x80, 0x00, 0x00]).unwrap_err(),
            KeyError::Der(_)
        ));
    }

    #[test]
    fn rejects_a_point_that_is_not_uncompressed_p256() {
        let key = PublicKey::from_pem(crate::DEFAULT_PUBLIC_KEY_PEM).unwrap();
        // A compressed point (33 bytes) does not fit the 65-byte slot.
        assert_eq!(
            PublicKey::from_der(&spki_der(&key.point()[..33])).unwrap_err(),
            KeyError::Point
        );
        // 65 bytes but a compressed/infinity first octet.
        let mut wrong_prefix = key.point().to_vec();
        wrong_prefix[0] = 0x02;
        assert_eq!(
            PublicKey::from_der(&spki_der(&wrong_prefix)).unwrap_err(),
            KeyError::Point
        );
    }

    #[test]
    fn oid_rendering_covers_known_oids() {
        assert_eq!(
            oid_to_string(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
            "1.2.840.10045.3.1.7"
        );
        assert_eq!(
            oid_to_string(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            "1.2.840.10045.2.1"
        );
        assert_eq!(oid_to_string(&[]), "empty OID");
    }
}
