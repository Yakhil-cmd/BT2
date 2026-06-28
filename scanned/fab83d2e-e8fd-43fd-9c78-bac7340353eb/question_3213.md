# Q3213: cryptographic precompiles cost recording gap after modexp gas computation in `ModExp::required_gas`

## Question
Can an attacker cause modexp gas computation in `ModExp::required_gas` to complete useful work while `post_process` or `record_cost` accounts for too little of it, leading to Theft of gas?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `modexp gas computation in `ModExp::required_gas``
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: split useful work from the gas-recording phase after the targeted precompile.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Theft of gas
- Fast validation: Instrument precompile execution and confirm every successful path records the full charged cost before returning. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
