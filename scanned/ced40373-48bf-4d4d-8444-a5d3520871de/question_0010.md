# Q0010: voucher decimal accounting under amount boundary supply integrity

## Question
Can an unprivileged attacker enter through MsgConvertVouchers signed by address by controlling address, sdk.Coins, IbcCroDenom amount and denom ordering when the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid, then make 8-decimal IBC CRO convert into more 18-decimal EVM denom than was escrowed so that escrowed IBC CRO times 10^10 equals minted EVM denom fails and bank supply, module escrow, contract balances, and ERC totalSupply cannot diverge profitably, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/ibc.go::ConvertVouchersToEvmCoins
- Entrypoint: MsgConvertVouchers signed by address
- Attacker controls: address, sdk.Coins, IbcCroDenom amount and denom ordering; scenario focus: amount boundary plus supply integrity.
- Exploit idea: make 8-decimal IBC CRO convert into more 18-decimal EVM denom than was escrowed while the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid.
- Invariant to test: escrowed IBC CRO times 10^10 equals minted EVM denom; also verify bank supply, module escrow, contract balances, and ERC totalSupply cannot diverge profitably.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
