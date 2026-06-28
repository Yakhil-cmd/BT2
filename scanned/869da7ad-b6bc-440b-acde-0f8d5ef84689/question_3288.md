# Q3288: cryptographic precompiles output ambiguity from SHA256 and RIPEMD160 cost and output handling

## Question
Can an attacker craft input so that SHA256 and RIPEMD160 cost and output handling returns an output that multiple surrounding consumers could interpret differently, letting a caller treat a failure as success and cause Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `SHA256 and RIPEMD160 cost and output handling`
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: look for outputs whose meaning is not rigid enough for downstream code.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Decode the precompile output through every reachable consumer path and ensure all interpretations agree. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
