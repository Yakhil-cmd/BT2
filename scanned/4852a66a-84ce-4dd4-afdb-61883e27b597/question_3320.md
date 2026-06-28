# Q3320: cryptographic precompiles recoverability gap after BLS12-381 G1/G2 MSM input extraction

## Question
Can an attacker make BLS12-381 G1/G2 MSM input extraction enter a failed state that neither cleanly reverts nor enables a safe refund or retry path, stranding funds or system capacity and causing Theft of gas?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `BLS12-381 G1/G2 MSM input extraction`
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: target failure states around the precompile that are neither final success nor clean revert.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Theft of gas
- Fast validation: Enumerate recoverability after each distinct failure mode and assert there is always one safe compensation path. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
