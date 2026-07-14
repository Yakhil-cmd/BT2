# Q303: walletconnect via filterRequestedDappCommands 303

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `filterRequestedDappCommands` (packages/gui/src/electron/commands/filterRequestedDappCommands.ts) control chainId/account/fingerprint mismatch through a batch of rapid user-accessible actions and drive the sequence preview -> mutate controlled state -> confirm so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/filterRequestedDappCommands.ts` / `filterRequestedDappCommands`
- Entrypoint: dapp command permission prompt
- Attacker controls: chainId/account/fingerprint mismatch; through a batch of rapid user-accessible actions
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
