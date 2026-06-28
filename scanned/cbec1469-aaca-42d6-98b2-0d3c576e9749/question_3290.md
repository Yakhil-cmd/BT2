# Q3290: cryptographic precompiles resource amplification through SHA256 and RIPEMD160 cost and output handling

## Question
Can an attacker batch or repeat calls to SHA256 and RIPEMD160 cost and output handling through an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses so a small paid input expands into disproportionate CPU, memory, or promise work and causes Unbounded gas consumption?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `SHA256 and RIPEMD160 cost and output handling`
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: amplify a per-call underpricing or allocation bug at the named precompile.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Unbounded gas consumption
- Fast validation: Run a high-count local sequence and compare cumulative paid gas with measured work and any resulting balance drain. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
