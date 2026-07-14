# Q3300: walletconnect via if 3300

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `if` (packages/gui/src/hooks/useWalletConnect.ts) control session metadata with misleading origin/icon/name fields with a delayed metadata fetch and drive the sequence open notification -> resolve details -> execute so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnect.ts` / `if`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: session metadata with misleading origin/icon/name fields; with a delayed metadata fetch
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
