# Q0263: native-to-CRC21 auto deploy under address alias backing conservation

## Question
Can an unprivileged attacker enter through MsgConvertVouchers for non-IbcCroDenom native assets by controlling sender, denom, amount, auto-deploy state and mapping state when EVM, bech32, module, zero, or precompile-range addresses are chosen to collide semantically, then register or use the wrong auto-deployed CRC21 contract for a valuable denom so that one denom has one canonical backed contract and no duplicate redeemable supply fails and escrowed, burned, minted, locked, and released amounts conserve value exactly, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/evm.go::ConvertCoinFromNativeToCRC21
- Entrypoint: MsgConvertVouchers for non-IbcCroDenom native assets
- Attacker controls: sender, denom, amount, auto-deploy state and mapping state; scenario focus: address alias plus backing conservation.
- Exploit idea: register or use the wrong auto-deployed CRC21 contract for a valuable denom while EVM, bech32, module, zero, or precompile-range addresses are chosen to collide semantically.
- Invariant to test: one denom has one canonical backed contract and no duplicate redeemable supply; also verify escrowed, burned, minted, locked, and released amounts conserve value exactly.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: replay the same transaction sequence from exported genesis and assert deterministic balances and mappings. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
