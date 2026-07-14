# Q1249: walletconnect via isAllowedCommand 1249

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `isAllowedCommand` (packages/gui/src/electron/commands/isAllowedCommand.ts) control chainId/account/fingerprint mismatch with precision-boundary values and drive the sequence connect -> approve -> switch context -> execute so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isAllowedCommand.ts` / `isAllowedCommand`
- Entrypoint: dapp command permission prompt
- Attacker controls: chainId/account/fingerprint mismatch; with precision-boundary values
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
