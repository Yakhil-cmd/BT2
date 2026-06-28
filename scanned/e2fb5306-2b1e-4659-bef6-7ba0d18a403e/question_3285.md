# Q3285: cryptographic precompiles identity forgery through SHA256 and RIPEMD160 cost and output handling

## Question
Can an attacker make surrounding EVM code trust a forged account, promise, or environment identity returned by SHA256 and RIPEMD160 cost and output handling, then move value or authorization it should not and cause Theft of gas?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `SHA256 and RIPEMD160 cost and output handling`
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: abuse the semantics of the targeted environment-facing precompile output.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Theft of gas
- Fast validation: Cross-check the returned identity or environment value against the real runtime context under crafted call graphs. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
