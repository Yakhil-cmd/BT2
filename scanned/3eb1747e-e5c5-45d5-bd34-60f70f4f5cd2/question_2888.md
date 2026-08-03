# Q2888: proxy-assisted identity escape via identity set identity clear on People Kusama runtime

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Kusama runtime and control batched updates that mutate both identity deposits and transferable balances before finalization so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended, breaking the invariant that a username, sub-account deposit, or identity lock must not be consumed twice or stranded forever, and leading to critical - direct loss of funds through misrouted refund, slash, or asset movement?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: batched updates that mutate both identity deposits and transferable balances before finalization
- Exploit idea: makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended
- Invariant to test: a username, sub-account deposit, or identity lock must not be consumed twice or stranded forever
- Expected Immunefi impact: Critical - direct loss of funds through misrouted refund, slash, or asset movement
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
