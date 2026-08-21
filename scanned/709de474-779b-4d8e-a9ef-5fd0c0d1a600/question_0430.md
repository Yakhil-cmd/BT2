# Q430: delegate signable message domain in signable_message::on_chain_nep

## Question
Can an unprivileged attacker who submits a `SignedDelegateAction` meta-transaction through any public relayer, controlling the domain separator and payload of the signed delegate message, drive `core/primitives/src/signable_message.rs::on_chain_nep` to reuse a signature across message types or chains, breaking the invariant that every signed message type has a distinct, non-reusable domain, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `core/primitives/src/signable_message.rs` -> `on_chain_nep`
- Entrypoint: unprivileged attacker submits a `SignedDelegateAction` meta-transaction through any public relayer
- Attacker controls: the domain separator and payload of the signed delegate message
- Exploit idea: reuse a signature across message types or chains
- Invariant to test: every signed message type has a distinct, non-reusable domain
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
