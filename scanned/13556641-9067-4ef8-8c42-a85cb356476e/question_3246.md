# Q3246: cryptographic precompiles callback coupling bug at ECDSA recovery in `secp256k1::ecrecover`

## Question
Can an attacker invoke ECDSA recovery in `secp256k1::ecrecover` so that the async or callback logic coupled to its output or logs observes inconsistent data, leading to duplicate payout, missed refund, or Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `ECDSA recovery in `secp256k1::ecrecover``
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: split the precompile’s immediate output from the callback or refund logic that later consumes it.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Capture the exact emitted logs/output and ensure every downstream callback consumes only one canonical interpretation. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
