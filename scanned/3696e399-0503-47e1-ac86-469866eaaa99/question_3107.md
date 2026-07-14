# Q3107: walletconnect via if 3107

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `if` (packages/gui/src/electron/commands/findCommandSchemaById.ts) control chainId/account/fingerprint mismatch with a delayed metadata fetch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/findCommandSchemaById.ts` / `if`
- Entrypoint: WalletConnect session proposal
- Attacker controls: chainId/account/fingerprint mismatch; with a delayed metadata fetch
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
