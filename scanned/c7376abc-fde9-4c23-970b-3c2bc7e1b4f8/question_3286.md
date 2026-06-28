# Q3286: cryptographic precompiles callback coupling bug at SHA256 and RIPEMD160 cost and output handling

## Question
Can an attacker invoke SHA256 and RIPEMD160 cost and output handling so that the async or callback logic coupled to its output or logs observes inconsistent data, leading to duplicate payout, missed refund, or Unbounded gas consumption?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `SHA256 and RIPEMD160 cost and output handling`
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: split the precompile’s immediate output from the callback or refund logic that later consumes it.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Unbounded gas consumption
- Fast validation: Capture the exact emitted logs/output and ensure every downstream callback consumes only one canonical interpretation. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
