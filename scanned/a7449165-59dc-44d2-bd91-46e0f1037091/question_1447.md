# Q1447: walletconnect via if 1447

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `if` (packages/gui/src/util/isWalletConnectChainIdMainnet.ts) control previously granted bypass permission combined with profile switch with case-normalized identifiers and drive the sequence fetch -> cache -> refresh -> submit so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/util/isWalletConnectChainIdMainnet.ts` / `if`
- Entrypoint: WalletConnect session proposal
- Attacker controls: previously granted bypass permission combined with profile switch; with case-normalized identifiers
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
