# Q996: walletconnect via handleEnableWalletConnect 996

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `handleEnableWalletConnect` (packages/gui/src/components/walletConnect/WalletConnectConnections.tsx) control session metadata with misleading origin/icon/name fields with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectConnections.tsx` / `handleEnableWalletConnect`
- Entrypoint: WalletConnect session proposal
- Attacker controls: session metadata with misleading origin/icon/name fields; with a stale Redux cache
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
