//! Amadeus Protocol - Rust implementation with Elixir compatibility

use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

const MAGIC: &[u8; 3] = b"AMA";
const SHARD_SIZE: usize = 1024;
const SIGNED_SINGLE_FRAME_THRESHOLD: usize = 1300;
const ENCRYPTED_SINGLE_FRAME_THRESHOLD: usize = 1380;

type ReedSolomonResult = (u16, Vec<(u16, Vec<u8>)>);
type FrameHeaderResult = (Version3b, bool, BlsPk, u16, u16, u64, u32, usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version3b(pub [u8; 3]);

impl Version3b {
    pub fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self([major, minor, patch])
    }

    pub fn as_string(&self) -> String {
        format!("{}.{}.{}", self.0[0], self.0[1], self.0[2])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsPk(pub [u8; 48]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsSig(pub [u8; 96]);

impl BlsSig {
    pub fn from_bytes(bytes: [u8; 96]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 96] {
        &self.0
    }
}

impl BlsPk {
    pub fn from_bytes(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

pub mod bls_domains {
    pub const DST: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    pub const DST_POP: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    pub const DST_ATT: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ATTESTATION_";
    pub const DST_ENTRY: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ENTRY_";
    pub const DST_VRF: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_VRF_";
    pub const DST_TX: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_TX_";
    pub const DST_MOTION: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_MOTION_";
    pub const DST_NODE: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NODE_";
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct BlsSecretKey {
    inner: SecretKey,
}

impl BlsSecretKey {
    pub fn from_ikm(ikm: &[u8]) -> Result<Self, ProtoError> {
        if ikm.len() < 32 {
            return Err(ProtoError::Malformed);
        }
        let sk = SecretKey::key_gen(ikm, &[]).map_err(|_| ProtoError::Malformed)?;
        Ok(Self { inner: sk })
    }

    pub fn to_public_key(&self) -> BlsPk {
        let pk_blst = self.inner.sk_to_pk();
        let pk_bytes = pk_blst.to_bytes();
        BlsPk(pk_bytes)
    }

    pub fn sign_with_blake3_hash(&self, pk: &BlsPk, message: &[u8], domain: &[u8]) -> BlsSig {
        let mut hash_input = Vec::with_capacity(48 + message.len());
        hash_input.extend_from_slice(&pk.0);
        hash_input.extend_from_slice(message);
        let hash = blake3::hash(&hash_input);
        let signature = self.inner.sign(hash.as_bytes(), domain, &[]);
        let sig_bytes = signature.to_bytes();
        BlsSig(sig_bytes)
    }

    pub fn sign(&self, message: &[u8], domain: &[u8]) -> BlsSig {
        let signature = self.inner.sign(message, domain, &[]);
        let sig_bytes = signature.to_bytes();
        BlsSig(sig_bytes)
    }

    pub fn sign_proof_of_possession(&self) -> BlsSig {
        let pk = self.to_public_key();
        let signature = self.inner.sign(&pk.0, bls_domains::DST_POP, &[]);
        let sig_bytes = signature.to_bytes();
        BlsSig(sig_bytes)
    }
}

pub fn bls_verify(
    public_key: &BlsPk,
    signature: &BlsSig,
    message: &[u8],
    domain: &[u8],
) -> Result<bool, ProtoError> {
    let pk_blst = PublicKey::from_bytes(&public_key.0).map_err(|_| ProtoError::Malformed)?;
    let sig_blst = Signature::from_bytes(&signature.0).map_err(|_| ProtoError::Malformed)?;
    let result = sig_blst.verify(true, message, domain, &[], &pk_blst, true);
    Ok(result == blst::BLST_ERROR::BLST_SUCCESS)
}

pub fn bls_verify_with_blake3_hash(
    public_key: &BlsPk,
    signature: &BlsSig,
    pk: &BlsPk,
    message: &[u8],
    domain: &[u8],
) -> Result<bool, ProtoError> {
    let mut hash_input = Vec::with_capacity(48 + message.len());
    hash_input.extend_from_slice(&pk.0);
    hash_input.extend_from_slice(message);
    let hash = blake3::hash(&hash_input);
    bls_verify(public_key, signature, hash.as_bytes(), domain)
}

pub fn bls_aggregate_signatures(signatures: &[BlsSig]) -> Result<BlsSig, ProtoError> {
    if signatures.is_empty() {
        return Err(ProtoError::Malformed);
    }

    let mut sig_objects = Vec::new();
    for sig in signatures {
        let sig_blst = Signature::from_bytes(&sig.0).map_err(|_| ProtoError::Malformed)?;
        sig_objects.push(sig_blst);
    }

    let mut agg_sig = AggregateSignature::from_signature(&sig_objects[0]);
    for sig in &sig_objects[1..] {
        agg_sig
            .add_signature(sig, true)
            .map_err(|_| ProtoError::Malformed)?;
    }

    let final_sig = agg_sig.to_signature();
    let sig_bytes = final_sig.to_bytes();
    Ok(BlsSig(sig_bytes))
}
pub fn bls_generate_keypair(ikm: &[u8]) -> Result<(BlsSecretKey, BlsPk), ProtoError> {
    let sk = BlsSecretKey::from_ikm(ikm)?;
    let pk = sk.to_public_key();
    Ok((sk, pk))
}

#[derive(Error, Debug)]
pub enum ProtoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("malformed frame or payload")]
    Malformed,
    #[error("random number generation failed")]
    Random,
    #[error("invalid frame size: {0} bytes")]
    InvalidFrameSize(usize),
}

pub fn encode_unsigned_min_be(mut v: u128) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let mut tmp = [0u8; 16];
    let mut i = 16;
    while v > 0 {
        i -= 1;
        tmp[i] = (v & 0xff) as u8;
        v >>= 8;
    }
    tmp[i..].to_vec()
}

pub fn derive_key_v2(shared: &SharedSecret, ts_nanos: u64, iv: &[u8; 12]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared.as_slice());
    let ts = encode_unsigned_min_be(ts_nanos as u128);
    hasher.update(&ts);
    hasher.update(iv);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

#[allow(dead_code)]
fn aead_encrypt_iv_tag_ct(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).map_err(|_| ProtoError::Random)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProtoError::Encrypt)?;
    let nonce = Nonce::from_slice(&iv);
    let ct_plus_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| ProtoError::Encrypt)?;
    if ct_plus_tag.len() < 16 {
        return Err(ProtoError::Encrypt);
    }
    let (ct, tag) = ct_plus_tag.split_at(ct_plus_tag.len() - 16);
    let mut out = Vec::with_capacity(12 + 16 + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ct);
    Ok(out)
}

pub fn aead_decrypt_iv_tag_ct(key: &[u8; 32], iv_tag_ct: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if iv_tag_ct.len() < 28 {
        return Err(ProtoError::Malformed);
    }
    let iv: [u8; 12] = iv_tag_ct[0..12].try_into().unwrap();
    let tag = &iv_tag_ct[12..28];
    let ct = &iv_tag_ct[28..];
    let mut ct_plus_tag = Vec::with_capacity(ct.len() + 16);
    ct_plus_tag.extend_from_slice(ct);
    ct_plus_tag.extend_from_slice(tag);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProtoError::Decrypt)?;
    let nonce = Nonce::from_slice(&iv);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct_plus_tag,
                aad: &[],
            },
        )
        .map_err(|_| ProtoError::Decrypt)
}

pub fn rs_encode_take(payload: &[u8]) -> Result<ReedSolomonResult, ProtoError> {
    use reed_solomon_simd::ReedSolomonEncoder;

    let data_shards = payload.len().div_ceil(SHARD_SIZE).max(1);
    let parity_shards = data_shards;
    let total_shards = data_shards + parity_shards;

    let mut encoder = ReedSolomonEncoder::new(data_shards, parity_shards, SHARD_SIZE)
        .map_err(|_| ProtoError::Malformed)?;

    let mut shards = Vec::new();
    let mut shard_idx = 0u16;

    // Add original shards (matching Elixir implementation exactly)
    for chunk_start in (0..payload.len()).step_by(SHARD_SIZE) {
        let chunk_end = (chunk_start + SHARD_SIZE).min(payload.len());
        let chunk = &payload[chunk_start..chunk_end];

        // Create 1024-byte buffer initialized to 0 (matching Elixir line 47-48)
        let mut buffer = [0u8; SHARD_SIZE];
        buffer[..chunk.len()].copy_from_slice(chunk);

        encoder
            .add_original_shard(buffer)
            .map_err(|_| ProtoError::Malformed)?;
        shards.push((shard_idx, buffer.to_vec()));
        shard_idx += 1;
    }

    // Generate recovery shards
    let result = encoder.encode().map_err(|_| ProtoError::Malformed)?;
    for recovery_shard in result.recovery_iter() {
        shards.push((shard_idx, recovery_shard.to_vec()));
        shard_idx += 1;
    }

    // Take same number of shards as Elixir (data + 1 + data/4)
    let to_take = (data_shards + 1 + (data_shards / 4)).min(total_shards);
    let out: Vec<_> = shards.into_iter().take(to_take).collect();

    Ok((total_shards as u16, out))
}

pub fn build_signed_v2_frames_with_key(
    version: Version3b,
    secret_key: &BlsSecretKey,
    msg_compressed: &[u8],
    ts_nanos: u64,
) -> Result<Vec<Vec<u8>>, ProtoError> {
    let pk = secret_key.to_public_key();
    let signature = secret_key.sign_with_blake3_hash(&pk, msg_compressed, bls_domains::DST_NODE);
    build_signed_v2_frames(version, pk, signature, msg_compressed, ts_nanos)
}

pub fn build_signed_v2_frames(
    version: Version3b,
    pk: BlsPk,
    sig: BlsSig,
    msg_compressed: &[u8],
    ts_nanos: u64,
) -> Result<Vec<Vec<u8>>, ProtoError> {
    let mut frames = Vec::new();

    if msg_compressed.len() < SIGNED_SINGLE_FRAME_THRESHOLD {
        let mut f = Vec::with_capacity(3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 + msg_compressed.len());
        f.extend_from_slice(MAGIC);
        f.extend_from_slice(&version.0);
        f.push(0x01);
        f.extend_from_slice(&pk.0);
        f.extend_from_slice(&sig.0);
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&1u16.to_be_bytes());
        f.extend_from_slice(&ts_nanos.to_be_bytes());
        f.extend_from_slice(&(msg_compressed.len() as u32).to_be_bytes());
        f.extend_from_slice(msg_compressed);
        frames.push(f);
        return Ok(frames);
    }

    let (total, shards) = rs_encode_take(msg_compressed)?;
    for (idx, shard) in shards {
        let mut f = Vec::with_capacity(3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 + shard.len());

        f.extend_from_slice(MAGIC);
        f.extend_from_slice(&version.0);
        f.push(0x01);
        f.extend_from_slice(&pk.0);
        f.extend_from_slice(&sig.0);
        f.extend_from_slice(&idx.to_be_bytes());
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&ts_nanos.to_be_bytes());
        f.extend_from_slice(&(msg_compressed.len() as u32).to_be_bytes());
        f.extend_from_slice(&shard);

        frames.push(f);
    }
    Ok(frames)
}

pub fn build_encrypted_v2_frames(
    version: Version3b,
    pk: BlsPk,
    shared: &SharedSecret,
    msg_compressed: &[u8],
    ts_nanos: u64,
) -> Result<Vec<Vec<u8>>, ProtoError> {
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).map_err(|_| ProtoError::Random)?;
    build_encrypted_v2_frames_with_iv(version, pk, shared, msg_compressed, ts_nanos, &iv)
}

pub fn build_encrypted_v2_frames_with_iv(
    version: Version3b,
    pk: BlsPk,
    shared: &SharedSecret,
    msg_compressed: &[u8],
    ts_nanos: u64,
    iv: &[u8; 12],
) -> Result<Vec<Vec<u8>>, ProtoError> {
    let key = derive_key_v2(shared, ts_nanos, iv);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| ProtoError::Encrypt)?;
    let nonce = Nonce::from_slice(iv);
    let ct_plus_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: msg_compressed,
                aad: &[],
            },
        )
        .map_err(|_| ProtoError::Encrypt)?;

    if ct_plus_tag.len() < 16 {
        return Err(ProtoError::Encrypt);
    }

    let (ct, tag) = ct_plus_tag.split_at(ct_plus_tag.len() - 16);
    let mut payload = Vec::with_capacity(12 + 16 + ct.len());
    payload.extend_from_slice(iv);
    payload.extend_from_slice(tag);
    payload.extend_from_slice(ct);

    let mut frames = Vec::new();
    let original_size = payload.len() as u32;

    if payload.len() < ENCRYPTED_SINGLE_FRAME_THRESHOLD {
        let mut f = Vec::with_capacity(3 + 3 + 1 + 48 + 2 + 2 + 8 + 4 + payload.len());
        f.extend_from_slice(MAGIC);
        f.extend_from_slice(&version.0);
        f.push(0x00);
        f.extend_from_slice(&pk.0);
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&1u16.to_be_bytes());
        f.extend_from_slice(&ts_nanos.to_be_bytes());
        f.extend_from_slice(&original_size.to_be_bytes());
        f.extend_from_slice(&payload);
        frames.push(f);
        return Ok(frames);
    }

    let (total, shards) = rs_encode_take(&payload)?;
    for (idx, shard) in shards {
        let mut f = Vec::with_capacity(3 + 3 + 1 + 48 + 2 + 2 + 8 + 4 + shard.len());
        f.extend_from_slice(MAGIC);
        f.extend_from_slice(&version.0);
        f.push(0x00);
        f.extend_from_slice(&pk.0);
        f.extend_from_slice(&idx.to_be_bytes());
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&ts_nanos.to_be_bytes());
        f.extend_from_slice(&original_size.to_be_bytes());
        f.extend_from_slice(&shard);

        frames.push(f);
    }
    Ok(frames)
}

pub fn decrypt_v2_payload(
    shared: &SharedSecret,
    ts_nanos: u64,
    payload_iv_tag_ct: &[u8],
) -> Result<Vec<u8>, ProtoError> {
    if payload_iv_tag_ct.len() < 28 {
        return Err(ProtoError::Malformed);
    }
    let iv: [u8; 12] = payload_iv_tag_ct[0..12].try_into().unwrap();
    let key = derive_key_v2(shared, ts_nanos, &iv);
    aead_decrypt_iv_tag_ct(&key, payload_iv_tag_ct)
}

/// This is the hardcoded key used for basic UDP packet obfuscation in the Elixir implementation.
pub fn aes256_key_legacy() -> [u8; 32] {
    [
        0, 6, 2, 94, 44, 225, 200, 37, 227, 180, 114, 230, 230, 219, 177, 28, 80, 19, 72, 13, 196,
        129, 81, 216, 161, 36, 177, 212, 199, 6, 169, 26,
    ]
}

pub fn legacy_encrypt_pack(plaintext: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let key = aes256_key_legacy();
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).map_err(|_| ProtoError::Random)?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| ProtoError::Encrypt)?;
    let nonce = Nonce::from_slice(&iv);
    let ct_plus_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| ProtoError::Encrypt)?;

    if ct_plus_tag.len() < 16 {
        return Err(ProtoError::Encrypt);
    }

    let (ct, tag) = ct_plus_tag.split_at(ct_plus_tag.len() - 16);
    let mut out = Vec::with_capacity(12 + 16 + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ct);
    Ok(out)
}

pub fn legacy_decrypt_unpack(iv_tag_ct: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if iv_tag_ct.len() < 12 + 16 {
        return Err(ProtoError::Malformed);
    }
    let key = aes256_key_legacy();
    aead_decrypt_iv_tag_ct(&key, iv_tag_ct)
}

pub fn legacy_encrypt_pack_with_test_key_and_iv(plaintext: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"legacy_obfuscation_test_key");
    let key_digest = hasher.finalize();
    let key: [u8; 32] = key_digest.into();

    let iv = [154, 188, 222, 240, 17, 34, 51, 68, 85, 102, 119, 136];

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| ProtoError::Encrypt)?;
    let nonce = Nonce::from_slice(&iv);
    let ct_plus_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| ProtoError::Encrypt)?;

    if ct_plus_tag.len() < 16 {
        return Err(ProtoError::Encrypt);
    }

    let (ct, tag) = ct_plus_tag.split_at(ct_plus_tag.len() - 16);

    let mut out = Vec::with_capacity(12 + 16 + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ct);
    Ok(out)
}

pub fn legacy_decrypt_unpack_with_test_key(iv_tag_ct: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if iv_tag_ct.len() < 12 + 16 {
        return Err(ProtoError::Malformed);
    }

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"legacy_obfuscation_test_key");
    let key_digest = hasher.finalize();
    let key: [u8; 32] = key_digest.into();

    aead_decrypt_iv_tag_ct(&key, iv_tag_ct)
}

pub fn parse_v2_frame_header(frame: &[u8]) -> Result<FrameHeaderResult, ProtoError> {
    if frame.len() < 3 + 3 + 1 + 48 {
        return Err(ProtoError::Malformed);
    }

    let mut offset = 0;

    if &frame[offset..offset + 3] != MAGIC {
        return Err(ProtoError::Malformed);
    }
    offset += 3;

    let version = Version3b([frame[offset], frame[offset + 1], frame[offset + 2]]);
    offset += 3;

    let flag_byte = frame[offset];
    let is_signed = (flag_byte & 0x01) != 0;
    offset += 1;

    let mut pk_bytes = [0u8; 48];
    pk_bytes.copy_from_slice(&frame[offset..offset + 48]);
    let pk = BlsPk(pk_bytes);
    offset += 48;

    // For signed frames, skip signature
    if is_signed {
        if frame.len() < offset + 96 {
            return Err(ProtoError::Malformed);
        }
        offset += 96;
    }

    if frame.len() < offset + 2 + 2 + 8 + 4 {
        return Err(ProtoError::Malformed);
    }

    let shard_index = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    offset += 2;

    let shard_total = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    offset += 2;

    let timestamp = u64::from_be_bytes([
        frame[offset],
        frame[offset + 1],
        frame[offset + 2],
        frame[offset + 3],
        frame[offset + 4],
        frame[offset + 5],
        frame[offset + 6],
        frame[offset + 7],
    ]);
    offset += 8;

    let original_size = u32::from_be_bytes([
        frame[offset],
        frame[offset + 1],
        frame[offset + 2],
        frame[offset + 3],
    ]);
    offset += 4;

    Ok((
        version,
        is_signed,
        pk,
        shard_index,
        shard_total,
        timestamp,
        original_size,
        offset,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erlang_minimal_be_encoding() {
        // Test cases matching Erlang :binary.encode_unsigned/1 behavior
        assert_eq!(encode_unsigned_min_be(0), vec![0]);
        assert_eq!(encode_unsigned_min_be(0x7f), vec![0x7f]);
        assert_eq!(encode_unsigned_min_be(0x80), vec![0x80]);
        assert_eq!(encode_unsigned_min_be(0x100), vec![0x01, 0x00]);
        assert_eq!(encode_unsigned_min_be(0x010203), vec![0x01, 0x02, 0x03]);
        assert_eq!(
            encode_unsigned_min_be(0x12345678),
            vec![0x12, 0x34, 0x56, 0x78]
        );

        // Large number test
        let big_num = 0x123456789abcdef0u128;
        let encoded = encode_unsigned_min_be(big_num);
        assert_eq!(
            encoded,
            vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
        );
    }

    #[test]
    fn test_version3b() {
        let v = Version3b::new(1, 2, 3);
        assert_eq!(v.0, [1, 2, 3]);
        assert_eq!(v.as_string(), "1.2.3");
    }

    #[test]
    fn test_v2_encrypt_decrypt_roundtrip_small() {
        let version = Version3b([1, 2, 3]);
        let pk = BlsPk([7u8; 48]);
        let shared = SharedSecret::new(vec![9u8; 32]);
        let ts = 1_725_000_000_123_456u64;
        let msg = b"small compressed message";

        let frames = build_encrypted_v2_frames(version, pk, &shared, msg, ts).unwrap();
        assert_eq!(frames.len(), 1); // Should be single frame

        // Parse the frame to extract payload
        let (
            parsed_version,
            is_signed,
            parsed_pk,
            shard_index,
            shard_total,
            parsed_ts,
            _orig_size,
            payload_offset,
        ) = parse_v2_frame_header(&frames[0]).unwrap();

        assert_eq!(parsed_version, version);
        assert!(!is_signed);
        assert_eq!(parsed_pk, pk);
        assert_eq!(shard_index, 0);
        assert_eq!(shard_total, 1);
        assert_eq!(parsed_ts, ts);

        let payload = &frames[0][payload_offset..];
        let decrypted = decrypt_v2_payload(&shared, ts, payload).unwrap();
        assert_eq!(&decrypted, msg);
    }

    #[test]
    fn test_v2_encrypt_decrypt_roundtrip_large() {
        let version = Version3b([1, 2, 3]);
        let pk = BlsPk([42u8; 48]);
        let shared = SharedSecret::new(vec![123u8; 32]);
        let ts = 1_725_000_000_999_999u64;

        // Create a large message that will require sharding
        let msg = vec![0xAAu8; 5000];

        let frames = build_encrypted_v2_frames(version, pk, &shared, &msg, ts).unwrap();
        assert!(frames.len() > 1); // Should be multiple frames

        // For this test, we just verify the first frame structure
        let (
            parsed_version,
            is_signed,
            parsed_pk,
            shard_index,
            shard_total,
            parsed_ts,
            _orig_size,
            _payload_offset,
        ) = parse_v2_frame_header(&frames[0]).unwrap();

        assert_eq!(parsed_version, version);
        assert!(!is_signed);
        assert_eq!(parsed_pk, pk);
        assert_eq!(shard_index, 0);
        assert!(shard_total > 1);
        assert_eq!(parsed_ts, ts);
    }

    #[test]
    fn test_signed_frames_small() {
        let version = Version3b([2, 1, 0]);
        let pk = BlsPk([0xFFu8; 48]);
        let sig = BlsSig([0x42u8; 96]);
        let ts = 1_700_000_000_000_000u64;
        let msg = b"signed message content";

        let frames = build_signed_v2_frames(version, pk, sig, msg, ts).unwrap();
        assert_eq!(frames.len(), 1);

        let (
            parsed_version,
            is_signed,
            parsed_pk,
            shard_index,
            shard_total,
            parsed_ts,
            orig_size,
            payload_offset,
        ) = parse_v2_frame_header(&frames[0]).unwrap();

        assert_eq!(parsed_version, version);
        assert!(is_signed);
        assert_eq!(parsed_pk, pk);
        assert_eq!(shard_index, 0);
        assert_eq!(shard_total, 1);
        assert_eq!(parsed_ts, ts);
        assert_eq!(orig_size as usize, msg.len());

        // Verify payload matches original message
        let payload = &frames[0][payload_offset..];
        assert_eq!(payload, msg);
    }

    #[test]
    fn test_signed_frames_large() {
        let version = Version3b([3, 0, 1]);
        let pk = BlsPk([0x11u8; 48]);
        let sig = BlsSig([0x22u8; 96]);
        let ts = 1_800_000_000_000_000u64;

        // Large message requiring sharding
        let msg = vec![0x99u8; 3000];

        let frames = build_signed_v2_frames(version, pk, sig, &msg, ts).unwrap();
        assert!(frames.len() > 1);

        // Check first frame
        let (
            parsed_version,
            is_signed,
            parsed_pk,
            shard_index,
            shard_total,
            parsed_ts,
            orig_size,
            _,
        ) = parse_v2_frame_header(&frames[0]).unwrap();

        assert_eq!(parsed_version, version);
        assert!(is_signed);
        assert_eq!(parsed_pk, pk);
        assert_eq!(shard_index, 0);
        assert!(shard_total > 1);
        assert_eq!(parsed_ts, ts);
        assert_eq!(orig_size as usize, msg.len());
    }

    #[test]
    fn test_legacy_obfuscation_roundtrip() {
        let plaintext = b"legacy message for UDP obfuscation";
        let encrypted = legacy_encrypt_pack(plaintext).unwrap();

        // Verify structure: 12-byte IV + 16-byte tag + ciphertext
        assert!(encrypted.len() >= 12 + 16);
        assert_eq!(encrypted.len(), 12 + 16 + plaintext.len());

        let decrypted = legacy_decrypt_unpack(&encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aead_encrypt_decrypt_raw() {
        let key = [0x01u8; 32];
        let plaintext = b"test message for direct AES-GCM";

        let encrypted = aead_encrypt_iv_tag_ct(&key, plaintext).unwrap();
        assert_eq!(encrypted.len(), 12 + 16 + plaintext.len());

        let decrypted = aead_decrypt_iv_tag_ct(&key, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_key_derivation() {
        let shared = SharedSecret::new(vec![0x12u8; 32]);
        let ts_nanos = 1_725_000_000_123_456u64;
        let iv = [0x34u8; 12];

        let key1 = derive_key_v2(&shared, ts_nanos, &iv);
        let key2 = derive_key_v2(&shared, ts_nanos, &iv);

        // Same inputs should produce same key
        assert_eq!(key1, key2);

        // Different timestamp should produce different key
        let key3 = derive_key_v2(&shared, ts_nanos + 1, &iv);
        assert_ne!(key1, key3);

        // Different IV should produce different key
        let iv2 = [0x35u8; 12];
        let key4 = derive_key_v2(&shared, ts_nanos, &iv2);
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_reed_solomon_sharding() {
        // Test small payload that fits in one shard
        let small_payload = vec![0xAAu8; 500];
        let (total, shards) = rs_encode_take(&small_payload).unwrap();
        assert_eq!(total, 2); // 1 data + 1 parity
        assert_eq!(shards.len(), 2); // take data + 1 + floor(data/4) = 1 + 1 + 0 = 2

        // Test larger payload requiring multiple shards
        let large_payload = vec![0xBBu8; 3000];
        let (total, shards) = rs_encode_take(&large_payload).unwrap();
        let expected_data_shards = (3000 + 1023) / 1024; // = 3
        assert_eq!(total as usize, expected_data_shards * 2); // data + parity
        let expected_take = expected_data_shards + 1 + (expected_data_shards / 4);
        assert_eq!(shards.len(), expected_take);
    }

    #[test]
    fn test_frame_header_parsing_errors() {
        // Too short frame
        let short_frame = vec![0u8; 10];
        assert!(parse_v2_frame_header(&short_frame).is_err());

        // Wrong magic
        let mut bad_magic = vec![0u8; 200];
        bad_magic[0..3].copy_from_slice(b"BAD");
        assert!(parse_v2_frame_header(&bad_magic).is_err());
    }

    #[test]
    fn test_bls_key_generation() {
        let ikm = [42u8; 32];
        let (sk, pk) = bls_generate_keypair(&ikm).unwrap();

        // Verify the public key derived from secret key matches
        let pk2 = sk.to_public_key();
        assert_eq!(pk, pk2);

        // Public key should be 48 bytes
        assert_eq!(pk.as_bytes().len(), 48);
    }

    #[test]
    fn test_bls_signing_and_verification() {
        let ikm = [123u8; 32];
        let (sk, pk) = bls_generate_keypair(&ikm).unwrap();

        let message = b"test message for BLS signing";
        let domain = bls_domains::DST_NODE;

        // Test direct signing
        let signature = sk.sign(message, domain);
        let is_valid = bls_verify(&pk, &signature, message, domain).unwrap();
        assert!(is_valid);

        // Test with wrong message
        let wrong_message = b"wrong message";
        let is_valid_wrong = bls_verify(&pk, &signature, wrong_message, domain).unwrap();
        assert!(!is_valid_wrong);
    }

    #[test]
    fn test_bls_blake3_signing() {
        let ikm = [200u8; 32];
        let (sk, pk) = bls_generate_keypair(&ikm).unwrap();

        let message = b"test message for Blake3 hashing";
        let domain = bls_domains::DST_NODE;

        // Sign with Blake3 pre-hashing (matches Elixir)
        let signature = sk.sign_with_blake3_hash(&pk, message, domain);

        // Verify with Blake3 verification function
        let is_valid = bls_verify_with_blake3_hash(&pk, &signature, &pk, message, domain).unwrap();
        assert!(is_valid);

        // Test with wrong message
        let wrong_message = b"wrong message";
        let is_valid_wrong =
            bls_verify_with_blake3_hash(&pk, &signature, &pk, wrong_message, domain).unwrap();
        assert!(!is_valid_wrong);
    }

    #[test]
    fn test_bls_domain_separation() {
        let ikm = [100u8; 32];
        let (sk, pk) = bls_generate_keypair(&ikm).unwrap();

        let message = b"domain separation test";

        // Sign with NODE domain
        let sig_node = sk.sign(message, bls_domains::DST_NODE);

        // Sign with TX domain
        let sig_tx = sk.sign(message, bls_domains::DST_TX);

        // Signatures should be different
        assert_ne!(sig_node, sig_tx);

        // Each signature should only verify with its correct domain
        assert!(bls_verify(&pk, &sig_node, message, bls_domains::DST_NODE).unwrap());
        assert!(!bls_verify(&pk, &sig_node, message, bls_domains::DST_TX).unwrap());

        assert!(bls_verify(&pk, &sig_tx, message, bls_domains::DST_TX).unwrap());
        assert!(!bls_verify(&pk, &sig_tx, message, bls_domains::DST_NODE).unwrap());
    }

    #[test]
    fn test_bls_proof_of_possession() {
        let ikm = [77u8; 32];
        let (sk, pk) = bls_generate_keypair(&ikm).unwrap();

        let pop_signature = sk.sign_proof_of_possession();

        // Verify the proof of possession
        let is_valid =
            bls_verify(&pk, &pop_signature, pk.as_bytes(), bls_domains::DST_POP).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_signed_frame_with_real_bls() {
        let ikm = [50u8; 32];
        let (sk, _pk) = bls_generate_keypair(&ikm).unwrap();

        let version = Version3b([1, 2, 3]);
        let message = b"real BLS signature test";
        let timestamp = 1725000000000000u64;

        // Build signed frame with real BLS signature
        let frames = build_signed_v2_frames_with_key(version, &sk, message, timestamp).unwrap();
        assert_eq!(frames.len(), 1); // Should be single frame

        // Test frame parsing
        let (
            parsed_version,
            is_signed,
            _pk,
            shard_index,
            shard_total,
            parsed_ts,
            orig_size,
            payload_offset,
        ) = parse_v2_frame_header(&frames[0]).unwrap();

        assert_eq!(parsed_version, version);
        assert!(is_signed);
        assert_eq!(shard_index, 0);
        assert_eq!(shard_total, 1);
        assert_eq!(parsed_ts, timestamp);
        assert_eq!(orig_size as usize, message.len());

        // Verify payload matches original message
        let payload = &frames[0][payload_offset..];
        assert_eq!(payload, message);
    }

    #[test]
    fn test_bls_key_serialization() {
        let ikm = [33u8; 32];
        let (sk, pk) = bls_generate_keypair(&ikm).unwrap();

        // Test public key serialization
        let pk_bytes = pk.as_bytes();
        let pk2 = BlsPk::from_bytes(*pk_bytes);
        assert_eq!(pk, pk2);

        // Test signature serialization
        let message = b"serialization test";
        let signature = sk.sign(message, bls_domains::DST_NODE);
        let sig_bytes = signature.as_bytes();
        let signature2 = BlsSig::from_bytes(*sig_bytes);
        assert_eq!(signature, signature2);
    }
}
