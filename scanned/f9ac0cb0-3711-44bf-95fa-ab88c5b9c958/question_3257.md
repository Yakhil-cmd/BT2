# Q3257: cryptographic precompiles determinism gap in ECDSA recovery in `secp256k1::ecrecover`

## Question
Can an attacker trigger ECDSA recovery in `secp256k1::ecrecover` with the same logical input under two equivalent public entry conditions and obtain different outputs, costs, or state effects, eventually causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `ECDSA recovery in `secp256k1::ecrecover``
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: look for non-deterministic behavior at the targeted precompile boundary.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Replay equivalent calls under identical state and assert output bytes, logs, and charged gas are deterministic. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
