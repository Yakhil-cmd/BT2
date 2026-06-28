# Q3258: cryptographic precompiles cross-precompile confusion involving ECDSA recovery in `secp256k1::ecrecover`

## Question
Can an attacker combine ECDSA recovery in `secp256k1::ecrecover` with another reachable precompile through an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses so one precompile’s output is unsafe to trust as the other’s input, leading to Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `ECDSA recovery in `secp256k1::ecrecover``
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: compose precompiles in a way that exposes a mismatch in validation or semantics around the targeted one.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Chain the targeted precompile with its natural companion in EVM tests and assert composition cannot forge privileged meaning or underpriced work. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
