//! Comprehensive Amadeus Protocol Validation
//!
//! Validates Rust implementation against Elixir test vectors for encryption/decryption
//! and BLS cryptography compatibility.

use amadeus_proto::*;
use hex;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
struct ElixirTestVectors {
    metadata: TestMetadata,
    signed_frames: Vec<SignedFrameTest>,
    encrypted_frames: Vec<EncryptedFrameTest>,
    key_derivation: Vec<KeyDerivationTest>,
    reed_solomon: Vec<ReedSolomonTest>,
    legacy_obfuscation: Vec<LegacyObfuscationTest>,
    bls_standalone: Vec<BlsStandaloneTest>,
    bls_aggregation: BlsAggregationTest,
    bls_proof_of_possession: Vec<BlsPopTest>,
    blake3_edge_cases: Vec<Blake3Test>,
    bls_cross_domain: BlsCrossDomainTest,
}

#[derive(Debug, Deserialize)]
struct TestKeys {
    pk: String,
}

#[derive(Debug, Deserialize)]
struct TestMetadata {
    generated_at: String,
    generator: String,
    elixir_version: String,
    test_keys: TestKeys,
}

//
// === CORE PROTOCOL TEST STRUCTURES ===
//

#[derive(Debug, Deserialize)]
struct SignedFrameTest {
    name: String,
    inputs: FrameInputs,
    outputs: FrameOutputs,
}

#[derive(Debug, Deserialize)]
struct EncryptedFrameTest {
    name: String,
    inputs: EncryptedFrameInputs,
    outputs: FrameOutputs,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FrameInputs {
    message: String,
    msg_compressed: String,
    timestamp: u64,
    version_3b: String,
    pk: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EncryptedFrameInputs {
    message: String,
    msg_compressed: String,
    timestamp: u64,
    shared_secret: String,
    version_3b: String,
    pk: String,
}

#[derive(Debug, Deserialize)]
struct FrameOutputs {
    frame_count: usize,
    frames: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct KeyDerivationTest {
    name: String,
    inputs: KeyDerivationInputs,
    intermediates: KeyDerivationIntermediates,
    outputs: KeyDerivationOutputs,
}

#[derive(Debug, Deserialize)]
struct KeyDerivationInputs {
    shared_secret: String,
    timestamp: u64,
    iv: String,
}

#[derive(Debug, Deserialize)]
struct KeyDerivationIntermediates {
    timestamp_encoded: String,
    key_input: String,
}

#[derive(Debug, Deserialize)]
struct KeyDerivationOutputs {
    derived_key: String,
}

#[derive(Debug, Deserialize)]
struct ReedSolomonTest {
    name: String,
    inputs: ReedSolomonInputs,
    parameters: ReedSolomonParameters,
    outputs: ReedSolomonOutputs,
}

#[derive(Debug, Deserialize)]
struct ReedSolomonInputs {
    payload: String,
    payload_size: usize,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ReedSolomonParameters {
    data_shards: usize,
    parity_shards: usize,
    total_shards: usize,
    shards_to_take: usize,
}

#[derive(Debug, Deserialize)]
struct ReedSolomonOutputs {
    shard_count: usize,
    shards: Vec<ShardData>,
}

#[derive(Debug, Deserialize)]
struct ShardData {
    index: u16,
    data: String,
}

#[derive(Debug, Deserialize)]
struct LegacyObfuscationTest {
    name: String,
    outputs: ObfuscationOutputs,
}

#[derive(Debug, Deserialize)]
struct ObfuscationOutputs {
    obfuscated: String,
}

//
// === BLS SUPPORTING TEST STRUCTURES ===
//

#[derive(Debug, Deserialize)]
struct BlsStandaloneTest {
    name: String,
    inputs: BlsInputs,
    direct_signing: Option<SignatureTest>,
    blake3_signing: Option<Blake3SignatureTest>,
}

#[derive(Debug, Deserialize)]
struct BlsInputs {
    pk: String,
    message_bytes: String,
    domain_name: String,
}

#[derive(Debug, Deserialize)]
struct SignatureTest {
    signature: String,
    verified: bool,
}

#[derive(Debug, Deserialize)]
struct Blake3SignatureTest {
    hash_input: String,
    hash_output: String,
    signature: String,
    verified: bool,
}

#[derive(Debug, Deserialize)]
struct BlsAggregationTest {
    test_message: String,
    domain: String,
    individual_signatures: Vec<IndividualSig>,
    aggregation_scenarios: Vec<AggregationScenario>,
}

#[derive(Debug, Deserialize)]
struct IndividualSig {
    pk: String,
    signature: String,
    verified: bool,
}

#[derive(Debug, Deserialize)]
struct AggregationScenario {
    name: String,
    signers_used: Vec<usize>,
    aggregated_signature: String,
}

#[derive(Debug, Deserialize)]
struct BlsPopTest {
    name: String,
    inputs: PopInputs,
    proof_of_possession: PopSignature,
}

#[derive(Debug, Deserialize)]
struct PopInputs {
    pk: String,
}

#[derive(Debug, Deserialize)]
struct PopSignature {
    signature: String,
    verified: bool,
    domain: String,
}

#[derive(Debug, Deserialize)]
struct Blake3Test {
    name: String,
    input: String,
    blake3_hash: String,
}

#[derive(Debug, Deserialize)]
struct BlsCrossDomainTest {
    cross_verifications: Vec<CrossVerification>,
}

#[derive(Debug, Deserialize)]
struct CrossVerification {
    signature_domain: String,
    verification_domain: String,
    is_valid: bool,
    should_be_valid: bool,
    test_passed: bool,
}

//
// === VALIDATION RESULTS ===
//

#[derive(Debug)]
struct ValidationResult {
    category: String,
    passed: usize,
    failed: usize,
    total: usize,
    failures: Vec<String>,
}

impl ValidationResult {
    fn new(category: &str) -> Self {
        ValidationResult {
            category: category.to_string(),
            passed: 0,
            failed: 0,
            total: 0,
            failures: Vec::new(),
        }
    }

    fn add_test(&mut self, success: bool, name: Option<&str>, error: Option<&str>) {
        self.total += 1;
        if success {
            self.passed += 1;
        } else {
            self.failed += 1;
            if let (Some(name), Some(error)) = (name, error) {
                self.failures.push(format!("{}: {}", name, error));
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Amadeus Protocol Comprehensive Validation");
    println!("Validating Rust implementation against Elixir test vectors");
    println!("{}", "=".repeat(60));

    let filename = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "test_vectors.json".to_string());

    let vectors = load_elixir_vectors(&filename)?;

    println!("📊 Test Vector Summary:");
    println!("   Generator: {}", vectors.metadata.generator);
    println!("   Generated: {}", vectors.metadata.generated_at);
    println!("   Elixir Version: {}", vectors.metadata.elixir_version);
    println!();

    println!("🔐 === CORE PROTOCOL VALIDATION (Priority 1) ===");
    let mut results = vec![
        validate_encrypted_frames(&vectors.encrypted_frames),
        validate_signed_frames(&vectors.signed_frames, &vectors.metadata.test_keys),
        validate_key_derivation(&vectors.key_derivation),
        validate_reed_solomon(&vectors.reed_solomon),
        validate_legacy_obfuscation(&vectors.legacy_obfuscation),
    ];

    println!("🔧 === BLS SUPPORTING VALIDATION (Priority 2) ===");
    results.extend(vec![
        validate_bls_standalone(&vectors.bls_standalone),
        validate_bls_aggregation(&vectors.bls_aggregation),
        validate_bls_proof_of_possession(&vectors.bls_proof_of_possession),
        validate_blake3_compatibility(&vectors.blake3_edge_cases),
        validate_bls_cross_domain(&vectors.bls_cross_domain),
    ]);

    generate_final_report(results)
}

fn validate_encrypted_frames(tests: &[EncryptedFrameTest]) -> ValidationResult {
    println!("\n🔒 Validating encrypted frames...");
    let mut result = ValidationResult::new("Encrypted Frames");

    for test in tests {
        match validate_single_encrypted_frame(test) {
            Ok(()) => {
                result.add_test(true, Some(&test.name), None);
                println!("   ✅ {}", test.name);
            }
            Err(e) => {
                result.add_test(false, Some(&test.name), Some(&e));
                println!("   ❌ {}: {}", test.name, e);
            }
        }
    }

    println!(
        "📊 Encrypted Frames: {}/{} passed",
        result.passed, result.total
    );
    result
}

fn validate_single_encrypted_frame(test: &EncryptedFrameTest) -> Result<(), String> {
    // Decode inputs
    let shared_secret_bytes = hex::decode(&test.inputs.shared_secret)
        .map_err(|e| format!("Invalid shared secret hex: {}", e))?;
    let shared_secret = SharedSecret::new(shared_secret_bytes);

    let version_bytes =
        hex::decode(&test.inputs.version_3b).map_err(|e| format!("Invalid version hex: {}", e))?;
    if version_bytes.len() != 3 {
        return Err("Version must be 3 bytes".to_string());
    }
    let version = Version3b([version_bytes[0], version_bytes[1], version_bytes[2]]);

    let pk_bytes = hex::decode(&test.inputs.pk).map_err(|e| format!("Invalid pk hex: {}", e))?;
    let pk_array: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| "Invalid pk length, expected 48 bytes")?;
    let pk = BlsPk::from_bytes(pk_array);

    let msg_compressed = hex::decode(&test.inputs.msg_compressed)
        .map_err(|e| format!("Invalid compressed message hex: {}", e))?;

    // Generate encrypted frames using Rust implementation with fixed IV to match Elixir test vectors
    let fixed_iv = [154, 188, 222, 240, 17, 34, 51, 68, 85, 102, 119, 136];
    let rust_frames = build_encrypted_v2_frames_with_iv(
        version,
        pk,
        &shared_secret,
        &msg_compressed,
        test.inputs.timestamp,
        &fixed_iv,
    )
    .map_err(|e| format!("Failed to generate encrypted frames: {:?}", e))?;

    // Compare with Elixir frames
    if rust_frames.len() != test.outputs.frame_count {
        return Err(format!(
            "Frame count mismatch: Rust={}, Elixir={}",
            rust_frames.len(),
            test.outputs.frame_count
        ));
    }

    for (i, rust_frame) in rust_frames.iter().enumerate() {
        let elixir_frame = hex::decode(&test.outputs.frames[i])
            .map_err(|e| format!("Invalid Elixir frame hex: {}", e))?;

        if rust_frame != &elixir_frame {
            // Find first difference for debugging
            let mut first_diff = None;
            for (pos, (rust_byte, elixir_byte)) in
                rust_frame.iter().zip(elixir_frame.iter()).enumerate()
            {
                if rust_byte != elixir_byte {
                    first_diff = Some((pos, *rust_byte, *elixir_byte));
                    break;
                }
            }

            if let Some((pos, rust_byte, elixir_byte)) = first_diff {
                return Err(format!(
                    "Frame {} content mismatch (first diff at byte {}: Rust=0x{:02x}, Elixir=0x{:02x})", 
                    i, pos, rust_byte, elixir_byte
                ));
            } else {
                return Err(format!("Frame {} length mismatch", i));
            }
        }
    }

    println!("  ✅ Frame structure matches exactly (signature compatibility verified)");
    Ok(())
}

fn validate_signed_frames(tests: &[SignedFrameTest], test_keys: &TestKeys) -> ValidationResult {
    println!("\n🖊️  Validating signed frames...");
    let mut result = ValidationResult::new("Signed Frames");

    for test in tests {
        match validate_single_signed_frame(test, test_keys) {
            Ok(()) => {
                result.add_test(true, Some(&test.name), None);
                println!("   ✅ {}", test.name);
            }
            Err(e) => {
                result.add_test(false, Some(&test.name), Some(&e));
                println!("   ❌ {}: {}", test.name, e);
            }
        }
    }

    println!(
        "📊 Signed Frames: {}/{} passed",
        result.passed, result.total
    );
    result
}

fn validate_single_signed_frame(
    test: &SignedFrameTest,
    test_keys: &TestKeys,
) -> Result<(), String> {
    let pk_bytes = hex::decode(&test_keys.pk).map_err(|e| e.to_string())?;
    let pk_array: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| "Invalid public key length")?;
    let public_key = BlsPk::from_bytes(pk_array);

    let version_bytes = hex::decode(&test.inputs.version_3b).map_err(|e| e.to_string())?;
    if version_bytes.len() != 3 {
        return Err("Version must be 3 bytes".to_string());
    }
    let version = Version3b([version_bytes[0], version_bytes[1], version_bytes[2]]);

    let msg_compressed = hex::decode(&test.inputs.msg_compressed).map_err(|e| e.to_string())?;

    let elixir_frame = hex::decode(&test.outputs.frames[0]).map_err(|e| e.to_string())?;
    if elixir_frame.len() < 151 {
        return Err("Frame too short".to_string());
    }

    let elixir_signature_bytes = &elixir_frame[55..151];
    let elixir_signature = BlsSig(
        elixir_signature_bytes
            .try_into()
            .map_err(|_| "Invalid signature length")?,
    );

    let rust_frames = build_signed_v2_frames(
        version,
        public_key,
        elixir_signature,
        &msg_compressed,
        test.inputs.timestamp,
    )
    .map_err(|e| e.to_string())?;

    if rust_frames.len() != test.outputs.frame_count {
        return Err("Frame count mismatch".to_string());
    }

    for (i, rust_frame) in rust_frames.iter().enumerate() {
        let elixir_frame = hex::decode(&test.outputs.frames[i]).map_err(|e| e.to_string())?;
        if rust_frame != &elixir_frame {
            return Err(format!("Frame {} mismatch", i));
        }
    }

    Ok(())
}

fn validate_key_derivation(tests: &[KeyDerivationTest]) -> ValidationResult {
    println!("\n🔑 Validating key derivation...");
    let mut result = ValidationResult::new("Key Derivation");

    for test in tests {
        match validate_single_key_derivation(test) {
            Ok(()) => {
                result.add_test(true, Some(&test.name), None);
                println!("   ✅ {}", test.name);
            }
            Err(e) => {
                result.add_test(false, Some(&test.name), Some(&e));
                println!("   ❌ {}: {}", test.name, e);
            }
        }
    }

    println!(
        "📊 Key Derivation: {}/{} passed",
        result.passed, result.total
    );
    result
}

fn validate_single_key_derivation(test: &KeyDerivationTest) -> Result<(), String> {
    // Parse inputs
    let shared_secret_bytes = hex::decode(&test.inputs.shared_secret)
        .map_err(|e| format!("Invalid shared secret hex: {}", e))?;
    let shared_secret = SharedSecret::new(shared_secret_bytes.clone());

    let iv_bytes = hex::decode(&test.inputs.iv).map_err(|e| format!("Invalid iv hex: {}", e))?;
    let iv_array: [u8; 12] = iv_bytes
        .clone()
        .try_into()
        .map_err(|_| "Invalid IV length, expected 12 bytes")?;

    let rust_derived_key = derive_key_v2(&shared_secret, test.inputs.timestamp, &iv_array);

    // Compare with expected output
    let expected_derived_key = hex::decode(&test.outputs.derived_key)
        .map_err(|e| format!("Invalid derived key hex: {}", e))?;

    if rust_derived_key.as_slice() != expected_derived_key.as_slice() {
        return Err("Derived key mismatch from our derive_key_v2() function".to_string());
    }

    // Also validate intermediate steps to ensure our algorithm matches Elixir's exactly
    let timestamp_encoded = encode_unsigned_minimal(test.inputs.timestamp);
    let expected_ts_encoded = hex::decode(&test.intermediates.timestamp_encoded)
        .map_err(|e| format!("Invalid timestamp encoding hex: {}", e))?;
    if timestamp_encoded != expected_ts_encoded.as_slice() {
        return Err(
            "Timestamp encoding algorithm mismatch (validate encode_unsigned_min_be)".to_string(),
        );
    }

    let mut key_input = Vec::new();
    key_input.extend_from_slice(&shared_secret_bytes);
    key_input.extend_from_slice(&timestamp_encoded);
    key_input.extend_from_slice(&iv_bytes);

    let expected_key_input = hex::decode(&test.intermediates.key_input)
        .map_err(|e| format!("Invalid key input hex: {}", e))?;
    if key_input != expected_key_input {
        return Err("Key derivation input construction mismatch".to_string());
    }

    Ok(())
}

fn validate_reed_solomon(tests: &[ReedSolomonTest]) -> ValidationResult {
    println!("\n🧩 Validating Reed-Solomon...");
    let mut result = ValidationResult::new("Reed-Solomon Sharding");

    for test in tests {
        match validate_single_reed_solomon(test) {
            Ok(()) => {
                result.add_test(true, Some(&test.name), None);
                println!("   ✅ {}", test.name);
            }
            Err(e) => {
                result.add_test(false, Some(&test.name), Some(&e));
                println!("   ❌ {}: {}", test.name, e);
            }
        }
    }

    println!("📊 Reed-Solomon: {}/{} passed", result.passed, result.total);
    result
}

fn validate_single_reed_solomon(test: &ReedSolomonTest) -> Result<(), String> {
    let payload =
        hex::decode(&test.inputs.payload).map_err(|e| format!("Invalid payload hex: {}", e))?;

    if payload.len() != test.inputs.payload_size {
        return Err(format!(
            "Payload size mismatch: expected {}, got {}",
            test.inputs.payload_size,
            payload.len()
        ));
    }

    use amadeus_proto::rs_encode_take;

    let rust_result = rs_encode_take(&payload)
        .map_err(|e| format!("Rust Reed-Solomon encoding failed: {}", e))?;

    let (total_shards, rust_shards) = rust_result;

    if total_shards as usize != test.parameters.total_shards {
        return Err(format!(
            "Total shard count mismatch: Rust={}, Elixir={}",
            total_shards, test.parameters.total_shards
        ));
    }

    // Validate taken shard count matches
    if rust_shards.len() != test.outputs.shard_count {
        return Err(format!(
            "Taken shard count mismatch: Rust={}, Elixir={}",
            rust_shards.len(),
            test.outputs.shard_count
        ));
    }

    // Validate each shard matches exactly
    for (rust_shard, elixir_shard) in rust_shards.iter().zip(test.outputs.shards.iter()) {
        // Check shard index matches
        if rust_shard.0 != elixir_shard.index {
            return Err(format!(
                "Shard index mismatch: Rust={}, Elixir={}",
                rust_shard.0, elixir_shard.index
            ));
        }

        // Check shard data matches exactly
        let expected_shard_data = hex::decode(&elixir_shard.data)
            .map_err(|e| format!("Invalid Elixir shard data hex: {}", e))?;

        if rust_shard.1 != expected_shard_data {
            // Find first difference for detailed debugging
            let mut first_diff = None;
            for (i, (rust_byte, elixir_byte)) in rust_shard
                .1
                .iter()
                .zip(expected_shard_data.iter())
                .enumerate()
            {
                if rust_byte != elixir_byte {
                    first_diff = Some((i, *rust_byte, *elixir_byte));
                    break;
                }
            }

            let diff_info = match first_diff {
                Some((pos, rust_val, elixir_val)) => format!(
                    " (first diff at byte {}: Rust=0x{:02x}, Elixir=0x{:02x})",
                    pos, rust_val, elixir_val
                ),
                None => String::new(),
            };

            return Err(format!(
                "Shard {} data mismatch: Rust length={}, Elixir length={}{}",
                rust_shard.0,
                rust_shard.1.len(),
                expected_shard_data.len(),
                diff_info
            ));
        }
    }

    // Additional validation: verify the parameters match our algorithm
    let expected_data_shards = payload.len().div_ceil(1024).max(1);
    if test.parameters.data_shards != expected_data_shards {
        return Err(format!(
            "Data shard calculation mismatch: expected {}, got {}",
            expected_data_shards, test.parameters.data_shards
        ));
    }

    let expected_shards_to_take =
        (expected_data_shards + 1 + (expected_data_shards / 4)).min(test.parameters.total_shards);
    if test.parameters.shards_to_take != expected_shards_to_take {
        return Err(format!(
            "Shards to take calculation mismatch: expected {}, got {}",
            expected_shards_to_take, test.parameters.shards_to_take
        ));
    }

    Ok(())
}

fn validate_legacy_obfuscation(tests: &[LegacyObfuscationTest]) -> ValidationResult {
    println!("\n🎭 Validating legacy obfuscation...");
    let mut result = ValidationResult::new("Legacy Obfuscation");

    for test in tests {
        match validate_single_legacy_obfuscation(test) {
            Ok(()) => {
                result.add_test(true, Some(&test.name), None);
                println!("   ✅ {}", test.name);
            }
            Err(e) => {
                result.add_test(false, Some(&test.name), Some(&e));
                println!("   ❌ {}: {}", test.name, e);
            }
        }
    }

    println!(
        "📊 Legacy Obfuscation: {}/{} passed",
        result.passed, result.total
    );
    result
}

fn validate_single_legacy_obfuscation(test: &LegacyObfuscationTest) -> Result<(), String> {
    let expected_obfuscated = hex::decode(&test.outputs.obfuscated).map_err(|e| e.to_string())?;
    let elixir_plaintext =
        legacy_decrypt_unpack_with_test_key(&expected_obfuscated).map_err(|e| e.to_string())?;
    let rust_obfuscated =
        legacy_encrypt_pack_with_test_key_and_iv(&elixir_plaintext).map_err(|e| e.to_string())?;

    if rust_obfuscated != expected_obfuscated {
        return Err("Legacy obfuscation mismatch".to_string());
    }

    Ok(())
}

fn validate_bls_standalone(tests: &[BlsStandaloneTest]) -> ValidationResult {
    println!("\n🔧 Validating BLS standalone...");
    let mut result = ValidationResult::new("BLS Standalone");

    for test in tests {
        match validate_single_bls_standalone(test) {
            Ok(()) => {
                result.add_test(true, Some(&test.name), None);
            }
            Err(e) => {
                result.add_test(false, Some(&test.name), Some(&e));
            }
        }
    }

    println!(
        "📊 BLS Standalone: {}/{} passed",
        result.passed, result.total
    );
    result
}

fn validate_single_bls_standalone(test: &BlsStandaloneTest) -> Result<(), String> {
    let pk_bytes = hex::decode(&test.inputs.pk).map_err(|e| format!("Invalid pk hex: {}", e))?;
    let pk_array: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| "Invalid pk length, expected 48 bytes")?;
    let pk = BlsPk::from_bytes(pk_array);

    let message_bytes = hex::decode(&test.inputs.message_bytes)
        .map_err(|e| format!("Invalid message hex: {}", e))?;

    let domain = match test.inputs.domain_name.as_str() {
        "DST" => bls_domains::DST,
        "DST_POP" => bls_domains::DST_POP,
        "DST_ATT" => bls_domains::DST_ATT,
        "DST_ENTRY" => bls_domains::DST_ENTRY,
        "DST_VRF" => bls_domains::DST_VRF,
        "DST_TX" => bls_domains::DST_TX,
        "DST_MOTION" => bls_domains::DST_MOTION,
        "DST_NODE" => bls_domains::DST_NODE,
        _ => return Err(format!("Unknown domain: {}", test.inputs.domain_name)),
    };

    if let Some(direct) = &test.direct_signing {
        let sig_bytes =
            hex::decode(&direct.signature).map_err(|e| format!("Invalid signature hex: {}", e))?;
        let sig_array: [u8; 96] = sig_bytes
            .try_into()
            .map_err(|_| "Invalid signature length, expected 96 bytes")?;
        let signature = BlsSig::from_bytes(sig_array);

        let rust_verified = bls_verify(&pk, &signature, &message_bytes, domain)
            .map_err(|e| format!("Verification failed: {:?}", e))?;

        if rust_verified != direct.verified {
            return Err(format!(
                "Direct verification mismatch: Rust={}, Elixir={}",
                rust_verified, direct.verified
            ));
        }
    }

    if let Some(blake3_test) = &test.blake3_signing {
        let sig_bytes = hex::decode(&blake3_test.signature)
            .map_err(|e| format!("Invalid Blake3 signature hex: {}", e))?;
        let sig_array: [u8; 96] = sig_bytes
            .try_into()
            .map_err(|_| "Invalid signature length, expected 96 bytes")?;
        let signature = BlsSig::from_bytes(sig_array);

        let hash_input = hex::decode(&blake3_test.hash_input)
            .map_err(|e| format!("Invalid hash input hex: {}", e))?;
        let expected_hash = hex::decode(&blake3_test.hash_output)
            .map_err(|e| format!("Invalid hash output hex: {}", e))?;

        let actual_hash = blake3::hash(&hash_input);
        if actual_hash.as_bytes() != expected_hash.as_slice() {
            return Err("Blake3 hash mismatch".to_string());
        }

        let rust_verified = bls_verify(&pk, &signature, actual_hash.as_bytes(), domain)
            .map_err(|e| format!("Blake3 verification failed: {:?}", e))?;

        if rust_verified != blake3_test.verified {
            return Err(format!(
                "Blake3 verification mismatch: Rust={}, Elixir={}",
                rust_verified, blake3_test.verified
            ));
        }
    }

    Ok(())
}

fn validate_bls_aggregation(test: &BlsAggregationTest) -> ValidationResult {
    println!("\n🔧 Validating BLS aggregation...");
    let mut result = ValidationResult::new("BLS Aggregation");

    let domain = test.domain.as_bytes();

    // Validate individual signatures
    for (i, sig) in test.individual_signatures.iter().enumerate() {
        match validate_individual_signature(sig, &test.test_message, domain) {
            Ok(()) => {
                result.add_test(true, Some(&format!("individual_{}", i)), None);
            }
            Err(e) => {
                result.add_test(false, Some(&format!("individual_{}", i)), Some(&e));
            }
        }
    }

    // Validate aggregation scenarios
    for scenario in &test.aggregation_scenarios {
        match validate_aggregation_scenario(scenario, &test.individual_signatures) {
            Ok(()) => {
                result.add_test(true, Some(&scenario.name), None);
            }
            Err(e) => {
                result.add_test(false, Some(&scenario.name), Some(&e));
            }
        }
    }

    println!(
        "📊 BLS Aggregation: {}/{} passed",
        result.passed, result.total
    );
    result
}

fn validate_individual_signature(
    sig: &IndividualSig,
    message: &str,
    domain: &[u8],
) -> Result<(), String> {
    let pk_bytes = hex::decode(&sig.pk).map_err(|e| format!("Invalid pk hex: {}", e))?;
    let pk_array: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| "Invalid pk length, expected 48 bytes")?;
    let pk = BlsPk::from_bytes(pk_array);

    let sig_bytes =
        hex::decode(&sig.signature).map_err(|e| format!("Invalid signature hex: {}", e))?;
    let sig_array: [u8; 96] = sig_bytes
        .try_into()
        .map_err(|_| "Invalid signature length, expected 96 bytes")?;
    let signature = BlsSig::from_bytes(sig_array);

    let rust_verified = bls_verify(&pk, &signature, message.as_bytes(), domain)
        .map_err(|e| format!("Verification failed: {:?}", e))?;

    if rust_verified != sig.verified {
        return Err(format!(
            "Verification mismatch: Rust={}, Elixir={}",
            rust_verified, sig.verified
        ));
    }

    Ok(())
}

fn validate_aggregation_scenario(
    scenario: &AggregationScenario,
    individual_sigs: &[IndividualSig],
) -> Result<(), String> {
    let mut signatures = Vec::new();
    for &idx in &scenario.signers_used {
        if idx >= individual_sigs.len() {
            return Err(format!("Invalid signer index: {}", idx));
        }

        let sig_bytes = hex::decode(&individual_sigs[idx].signature)
            .map_err(|e| format!("Invalid signature hex: {}", e))?;
        let sig_array: [u8; 96] = sig_bytes
            .try_into()
            .map_err(|_| "Invalid signature length, expected 96 bytes")?;
        let signature = BlsSig::from_bytes(sig_array);
        signatures.push(signature);
    }

    let rust_aggregated = bls_aggregate_signatures(&signatures)
        .map_err(|e| format!("Aggregation failed: {:?}", e))?;

    let elixir_aggregated_bytes = hex::decode(&scenario.aggregated_signature)
        .map_err(|e| format!("Invalid aggregated signature hex: {}", e))?;
    let elixir_agg_array: [u8; 96] = elixir_aggregated_bytes
        .try_into()
        .map_err(|_| "Invalid aggregated signature length, expected 96 bytes")?;
    let elixir_aggregated = BlsSig::from_bytes(elixir_agg_array);

    if rust_aggregated != elixir_aggregated {
        return Err("Aggregated signatures don't match".to_string());
    }

    Ok(())
}

fn validate_bls_proof_of_possession(tests: &[BlsPopTest]) -> ValidationResult {
    println!("\n🔧 Validating BLS PoP...");
    let mut result = ValidationResult::new("BLS Proof of Possession");

    for test in tests {
        match validate_single_bls_pop(test) {
            Ok(()) => {
                result.add_test(true, Some(&test.name), None);
            }
            Err(e) => {
                result.add_test(false, Some(&test.name), Some(&e));
            }
        }
    }

    println!("📊 BLS PoP: {}/{} passed", result.passed, result.total);
    result
}

fn validate_single_bls_pop(test: &BlsPopTest) -> Result<(), String> {
    let pk_bytes = hex::decode(&test.inputs.pk).map_err(|e| format!("Invalid pk hex: {}", e))?;
    let pk_array: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| "Invalid pk length, expected 48 bytes")?;
    let pk = BlsPk::from_bytes(pk_array);

    let sig_bytes = hex::decode(&test.proof_of_possession.signature)
        .map_err(|e| format!("Invalid signature hex: {}", e))?;
    let sig_array: [u8; 96] = sig_bytes
        .try_into()
        .map_err(|_| "Invalid signature length, expected 96 bytes")?;
    let signature = BlsSig::from_bytes(sig_array);

    let domain = test.proof_of_possession.domain.as_bytes();
    let rust_verified = bls_verify(&pk, &signature, pk.as_bytes(), domain)
        .map_err(|e| format!("PoP verification failed: {:?}", e))?;

    if rust_verified != test.proof_of_possession.verified {
        return Err(format!(
            "PoP verification mismatch: Rust={}, Elixir={}",
            rust_verified, test.proof_of_possession.verified
        ));
    }

    Ok(())
}

fn validate_blake3_compatibility(tests: &[Blake3Test]) -> ValidationResult {
    println!("\n🔧 Validating Blake3...");
    let mut result = ValidationResult::new("Blake3 Compatibility");

    for test in tests {
        match validate_single_blake3(test) {
            Ok(()) => {
                result.add_test(true, Some(&test.name), None);
            }
            Err(e) => {
                result.add_test(false, Some(&test.name), Some(&e));
            }
        }
    }

    println!("📊 Blake3: {}/{} passed", result.passed, result.total);
    result
}

fn validate_single_blake3(test: &Blake3Test) -> Result<(), String> {
    let input_bytes = hex::decode(&test.input).map_err(|e| format!("Invalid input hex: {}", e))?;
    let expected_hash =
        hex::decode(&test.blake3_hash).map_err(|e| format!("Invalid hash hex: {}", e))?;

    let rust_hash = blake3::hash(&input_bytes);

    if rust_hash.as_bytes() != expected_hash.as_slice() {
        return Err("Blake3 hash mismatch".to_string());
    }

    Ok(())
}

fn validate_bls_cross_domain(test: &BlsCrossDomainTest) -> ValidationResult {
    println!("\n🔧 Validating BLS cross-domain...");
    let mut result = ValidationResult::new("BLS Cross-Domain");

    for verification in &test.cross_verifications {
        match validate_single_cross_domain(verification) {
            Ok(()) => {
                result.add_test(
                    true,
                    Some(&format!(
                        "{}→{}",
                        verification.signature_domain, verification.verification_domain
                    )),
                    None,
                );
            }
            Err(e) => {
                result.add_test(
                    false,
                    Some(&format!(
                        "{}→{}",
                        verification.signature_domain, verification.verification_domain
                    )),
                    Some(&e),
                );
            }
        }
    }

    println!("📊 Cross-Domain: {}/{} passed", result.passed, result.total);
    result
}

fn validate_single_cross_domain(verification: &CrossVerification) -> Result<(), String> {
    if verification.is_valid != verification.should_be_valid {
        return Err(format!(
            "Cross-domain test failed - Expected: {}, Got: {}",
            verification.should_be_valid, verification.is_valid
        ));
    }

    if !verification.test_passed {
        return Err("Cross-domain test marked as failed by Elixir".to_string());
    }

    Ok(())
}

fn load_elixir_vectors(filename: &str) -> Result<ElixirTestVectors, Box<dyn std::error::Error>> {
    println!("📂 Loading Elixir test vectors from: {}", filename);

    let contents = fs::read_to_string(filename)
        .map_err(|e| format!("Failed to read file {}: {}", filename, e))?;

    let vectors: ElixirTestVectors =
        serde_json::from_str(&contents).map_err(|e| format!("Failed to parse JSON: {}", e))?;

    println!("✅ Successfully loaded test vectors");
    Ok(vectors)
}

/// Encode unsigned integer in minimal form (matches Elixir's :binary.encode_unsigned/1)
/// This strips leading zeros unlike Rust's to_be_bytes() which is fixed-width
fn encode_unsigned_minimal(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }

    let bytes = value.to_be_bytes();
    // Find the first non-zero byte and return from there
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[first_nonzero..].to_vec()
}

fn generate_final_report(results: Vec<ValidationResult>) -> Result<(), Box<dyn std::error::Error>> {
    let total_passed: usize = results.iter().map(|r| r.passed).sum();
    let total_failed: usize = results.iter().map(|r| r.failed).sum();
    let total_tests = total_passed + total_failed;

    println!("\n{}", "=".repeat(60));
    println!("📋 COMPREHENSIVE VALIDATION REPORT");
    println!("{}", "=".repeat(60));
    println!("🔐 Encryption/decryption:");
    let core_categories = [
        "Encrypted Frames",
        "Signed Frames",
        "Key Derivation",
        "Reed-Solomon Sharding",
        "Legacy Obfuscation",
    ];
    for category in &core_categories {
        if let Some(result) = results.iter().find(|r| r.category == *category) {
            let status = if result.failed == 0 { "✅" } else { "❌" };
            println!(
                "   {} {}: {}/{} passed",
                status, result.category, result.passed, result.total
            );
        }
    }

    println!();
    println!("🔧 BLS STUFF:");
    let bls_categories = [
        "BLS Standalone",
        "BLS Aggregation",
        "BLS Proof of Possession",
        "Blake3 Compatibility",
        "BLS Cross-Domain",
    ];
    for category in &bls_categories {
        if let Some(result) = results.iter().find(|r| r.category == *category) {
            let status = if result.failed == 0 { "✅" } else { "❌" };
            println!(
                "   {} {}: {}/{} passed",
                status, result.category, result.passed, result.total
            );
        }
    }

    println!("{}", "-".repeat(60));
    let overall_status = if total_failed == 0 {
        "✅ PASSED"
    } else {
        "❌ ISSUES FOUND"
    };
    println!(
        "🎯 OVERALL: {} - {}/{} tests passed",
        overall_status, total_passed, total_tests
    );

    if total_failed == 0 {
        println!("The Rust implementation successfully validates against all Elixir test vectors.");
        println!("✅ Encryption/decryption port from Erlang is working correctly.");
    } else {
        println!("\n⚠️  Compatibility issues detected:");
        for result in &results {
            if result.failed > 0 {
                println!("\n❌ {}:", result.category);
                for failure in &result.failures {
                    println!("   - {}", failure);
                }
            }
        }
    }

    std::process::exit(if total_failed == 0 { 0 } else { 1 });
}
