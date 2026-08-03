# Q3634: cross-ceremony state bleed via runtimecall encointercommunities signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerCommunities` signed user path on Encointer runtime and control offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries so that `impl_runtime_apis! / XCM payment and dry-run APIs` causes a payout, faucet action, or bazaar settlement to finalize locally without the matching burn, hold, or reputation consumption, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to high - severe degradation or halt of a critical community-payment path?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `RuntimeCall::EncointerCommunities` signed user path
- Attacker controls: offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries
- Exploit idea: causes a payout, faucet action, or bazaar settlement to finalize locally without the matching burn, hold, or reputation consumption
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: High - severe degradation or halt of a critical community-payment path
- Fast validation: xcm or proxy integration test if the path depends on aliased or remote execution
