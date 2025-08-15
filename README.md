# Amadeus Protocol encode/decode - Rust Implementation

A simple Rust implementation of the Amadeus protocol encode/decode mirroring the original Elixir implementation.

## Compatibility

This implementation passes an extensive set of test vectors from the Elixir reference implementation, ensuring byte-for-byte compatibility for:
- Signed frame generation
- Encrypted frame generation  
- Legacy UDP obfuscation
- Reed-Solomon sharding
- Key derivation
- BLS cryptographic operations

Run compatibility validation: `cargo run --example comprehensive_validation`

The test vectors were generated using the Elixir implementation and can be swapped by changing the `test_vectors.json` file.

## Contributing

Contributions are welcome! Please ensure:
- All tests pass: `cargo test`
- Code is properly formatted: `cargo fmt`
- No clippy warnings: `cargo clippy`
- Maintain compatibility with the original Elixir implementation