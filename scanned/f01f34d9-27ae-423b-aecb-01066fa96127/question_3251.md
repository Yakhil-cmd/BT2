# Q3251: cryptographic precompiles address aliasing around ECDSA recovery in `secp256k1::ecrecover`

## Question
Can an attacker reach ECDSA recovery in `secp256k1::ecrecover` through an aliased or unexpected precompile address under an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses, bypassing the address-specific assumptions of surrounding code and causing Theft of gas?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `ECDSA recovery in `secp256k1::ecrecover``
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: look for address-level confusion in the precompile set or downstream consumers.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Theft of gas
- Fast validation: Probe all configured precompile addresses and confirm only the intended address family reaches the targeted logic. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
