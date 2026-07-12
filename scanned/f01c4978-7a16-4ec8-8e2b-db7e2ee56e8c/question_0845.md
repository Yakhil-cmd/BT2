# Q0845: voucher source extraction under same-block reorder channel provenance

## Question
Can an unprivileged attacker enter through IBC voucher transfer path by controlling voucher denom, source channel trace, receiver and amount when two attacker-controlled transactions are valid separately but reordered in one block, then derive a wrong source channel for voucher redemption so that voucher routing uses the original denom trace and cannot be attacker-selected fails and IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/params.go::GetSourceChannelID
- Entrypoint: IBC voucher transfer path
- Attacker controls: voucher denom, source channel trace, receiver and amount; scenario focus: same-block reorder plus channel provenance.
- Exploit idea: derive a wrong source channel for voucher redemption while two attacker-controlled transactions are valid separately but reordered in one block.
- Invariant to test: voucher routing uses the original denom trace and cannot be attacker-selected; also verify IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
