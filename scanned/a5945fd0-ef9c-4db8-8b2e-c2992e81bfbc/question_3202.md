# Q3202: beneficiary resolution split via signed user flow that on Coretime Polkadot XCM

## Question
Can an unprivileged attacker enter through `signed user flow that reaches Coretime Polkadot through valid upstream XCM` on Coretime Polkadot XCM and control a location that can be interpreted differently across aliasing, account conversion, and asset transacting code so that `FeeManager / ExecuteXcmOrigin` causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume, breaking the invariant that asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/xcm_config.rs` :: `FeeManager / ExecuteXcmOrigin`
- Entrypoint: `signed user flow that reaches Coretime Polkadot through valid upstream XCM`
- Attacker controls: a location that can be interpreted differently across aliasing, account conversion, and asset transacting code
- Exploit idea: causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume
- Invariant to test: asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary
