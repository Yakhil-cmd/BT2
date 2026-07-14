# Q1637: walletconnect via shouldRouteDappNotification 1637

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `shouldRouteDappNotification` (packages/gui/src/util/shouldRouteDappNotification.ts) control chainId/account/fingerprint mismatch with hidden Unicode characters and drive the sequence connect -> approve -> switch context -> execute so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/util/shouldRouteDappNotification.ts` / `shouldRouteDappNotification`
- Entrypoint: pairing URI/import flow
- Attacker controls: chainId/account/fingerprint mismatch; with hidden Unicode characters
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
