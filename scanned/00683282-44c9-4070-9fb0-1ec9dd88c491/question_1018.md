# Q1018: walletconnect via parseRoyaltyPercentage 1018

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `parseRoyaltyPercentage` (packages/gui/src/electron/commands/parseCommandDisplay.ts) control session metadata with misleading origin/icon/name fields with a delayed metadata fetch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/parseCommandDisplay.ts` / `parseRoyaltyPercentage`
- Entrypoint: stored dapp permission reload
- Attacker controls: session metadata with misleading origin/icon/name fields; with a delayed metadata fetch
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
