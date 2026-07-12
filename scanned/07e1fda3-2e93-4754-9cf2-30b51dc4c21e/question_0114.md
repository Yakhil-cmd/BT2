# Q0114: multi-coin conversion atomicity under duplicate ordering mapping uniqueness

## Question
Can an unprivileged attacker enter through MsgConvertVouchers with multiple coins by controlling coin list order, one valid coin, one failing coin and sender balance when the attacker repeats or reorders value-bearing items inside one transaction or receipt, then commit an earlier conversion before a later coin returns an error so that failed conversion rolls back every bank and EVM side effect fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/ibc.go::ConvertVouchersToEvmCoins
- Entrypoint: MsgConvertVouchers with multiple coins
- Attacker controls: coin list order, one valid coin, one failing coin and sender balance; scenario focus: duplicate ordering plus mapping uniqueness.
- Exploit idea: commit an earlier conversion before a later coin returns an error while the attacker repeats or reorders value-bearing items inside one transaction or receipt.
- Invariant to test: failed conversion rolls back every bank and EVM side effect; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
