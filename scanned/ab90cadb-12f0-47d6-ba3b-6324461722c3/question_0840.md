# Q0840: voucher source extraction under failed tail call supply integrity

## Question
Can an unprivileged attacker enter through IBC voucher transfer path by controlling voucher denom, source channel trace, receiver and amount when a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run, then derive a wrong source channel for voucher redemption so that voucher routing uses the original denom trace and cannot be attacker-selected fails and bank supply, module escrow, contract balances, and ERC totalSupply cannot diverge profitably, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/params.go::GetSourceChannelID
- Entrypoint: IBC voucher transfer path
- Attacker controls: voucher denom, source channel trace, receiver and amount; scenario focus: failed tail call plus supply integrity.
- Exploit idea: derive a wrong source channel for voucher redemption while a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run.
- Invariant to test: voucher routing uses the original denom trace and cannot be attacker-selected; also verify bank supply, module escrow, contract balances, and ERC totalSupply cannot diverge profitably.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
