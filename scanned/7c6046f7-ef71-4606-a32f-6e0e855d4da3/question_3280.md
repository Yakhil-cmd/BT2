# Q3280: cryptographic precompiles recoverability gap after secp256r1 input validation and output semantics

## Question
Can an attacker make secp256r1 input validation and output semantics enter a failed state that neither cleanly reverts nor enables a safe refund or retry path, stranding funds or system capacity and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `secp256r1 input validation and output semantics`
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: target failure states around the precompile that are neither final success nor clean revert.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Enumerate recoverability after each distinct failure mode and assert there is always one safe compensation path. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
