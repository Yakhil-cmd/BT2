# Q1805: meta-transaction replay in verifier::verify_nonce

## Question
Can an unprivileged attacker who submits a `SignedDelegateAction` meta-transaction through any public relayer, controlling delegate nonce, `max_block_height`, and repeated relayer submissions, drive `runtime/runtime/src/verifier.rs::verify_nonce` to replay one signed delegate action into more than one executed receipt, breaking the invariant that a signed delegate action can be executed at most once, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `verify_nonce`
- Entrypoint: unprivileged attacker submits a `SignedDelegateAction` meta-transaction through any public relayer
- Attacker controls: delegate nonce, `max_block_height`, and repeated relayer submissions
- Exploit idea: replay one signed delegate action into more than one executed receipt
- Invariant to test: a signed delegate action can be executed at most once
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
