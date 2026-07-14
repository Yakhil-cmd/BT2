# Q2334: walletconnect via openPairDialog 2334

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `openPairDialog` (packages/gui/src/electron/utils/openPairDialog.ts) control session metadata with misleading origin/icon/name fields with a delayed metadata fetch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/openPairDialog.ts` / `openPairDialog`
- Entrypoint: dapp command permission prompt
- Attacker controls: session metadata with misleading origin/icon/name fields; with a delayed metadata fetch
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
