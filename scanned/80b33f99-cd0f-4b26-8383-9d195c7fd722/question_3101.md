# Q3101: walletconnect via processDappCommands 3101

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `processDappCommands` (packages/gui/src/electron/commands/DappCommands.ts) control chainId/account/fingerprint mismatch after canceling and reopening the dialog and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/DappCommands.ts` / `processDappCommands`
- Entrypoint: WalletConnect session proposal
- Attacker controls: chainId/account/fingerprint mismatch; after canceling and reopening the dialog
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
