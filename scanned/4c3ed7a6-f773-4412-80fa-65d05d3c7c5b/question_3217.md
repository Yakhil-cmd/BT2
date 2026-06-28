# Q3217: cryptographic precompiles determinism gap in modexp gas computation in `ModExp::required_gas`

## Question
Can an attacker trigger modexp gas computation in `ModExp::required_gas` with the same logical input under two equivalent public entry conditions and obtain different outputs, costs, or state effects, eventually causing Theft of gas?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `modexp gas computation in `ModExp::required_gas``
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: look for non-deterministic behavior at the targeted precompile boundary.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Theft of gas
- Fast validation: Replay equivalent calls under identical state and assert output bytes, logs, and charged gas are deterministic. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
