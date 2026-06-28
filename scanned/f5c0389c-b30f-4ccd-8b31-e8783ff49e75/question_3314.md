# Q3314: cryptographic precompiles hardfork selection gap affecting BLS12-381 G1/G2 MSM input extraction

## Question
Can an attacker rely on an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses to select a hardfork-specific precompile behavior around BLS12-381 G1/G2 MSM input extraction that differs from the rest of the engine’s assumptions, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine-precompiles/src/modexp.rs + alt_bn256.rs + secp256k1.rs + secp256r1.rs + hash.rs + bls12_381/*` -> `BLS12-381 G1/G2 MSM input extraction`
- Entrypoint: an EVM transaction through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes Aurora’s cryptographic precompile addresses
- Attacker controls: precompile input bytes, calldata length, gas limit, repeated calls, and contract code that depends on the precompile output
- Exploit idea: look for precompile-set construction mismatches across hardfork constructors or engine config.
- Invariant to test: crypto precompiles must charge sufficient gas, reject malformed input consistently, and never let user-controlled input misprice work or forge privileged meaning
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Instantiate the precompile set under the active config and verify the targeted behavior and address map match the engine’s execution assumptions. write EVM tests that call the relevant precompile with boundary-size and malformed inputs, then assert gas charged, output bytes, and surrounding call effects stay correct
