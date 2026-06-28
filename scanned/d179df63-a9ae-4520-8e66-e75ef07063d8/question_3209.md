# Q3209: cryptographic precompiles revert-versus-success split in modexp gas computation in `ModExp::required_gas`

## Question
Can an attacker make modexp gas computation in `ModExp::required_gas` turn what should be a reverting path into a successful return with sentinel bytes, or vice versa, so the surrounding engine violates crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning and causes Theft of gas?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `modexp gas computation in `ModExp::required_gas``
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: split failure signaling from actual effect at the targeted precompile.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Theft of gas
- Fast validation: Enumerate malformed and edge-case inputs and compare exit status with any returned bytes, logs, and state effects. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
