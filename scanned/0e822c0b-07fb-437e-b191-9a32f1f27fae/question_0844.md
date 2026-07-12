# Q0844: voucher source extraction under same-block reorder mapping uniqueness

## Question
Can an unprivileged attacker enter through IBC voucher transfer path by controlling voucher denom, source channel trace, receiver and amount when two attacker-controlled transactions are valid separately but reordered in one block, then derive a wrong source channel for voucher redemption so that voucher routing uses the original denom trace and cannot be attacker-selected fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/params.go::GetSourceChannelID
- Entrypoint: IBC voucher transfer path
- Attacker controls: voucher denom, source channel trace, receiver and amount; scenario focus: same-block reorder plus mapping uniqueness.
- Exploit idea: derive a wrong source channel for voucher redemption while two attacker-controlled transactions are valid separately but reordered in one block.
- Invariant to test: voucher routing uses the original denom trace and cannot be attacker-selected; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
