# Q297: walletconnect via getOffer 297

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `getOffer` (packages/gui/src/electron/commands/Commands.ts) control session metadata with misleading origin/icon/name fields with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/Commands.ts` / `getOffer`
- Entrypoint: dapp command permission prompt
- Attacker controls: session metadata with misleading origin/icon/name fields; with hidden Unicode characters
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
