# Q1525: walletconnect via visibleParams 1525

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `visibleParams` (packages/gui/src/electron/commands/humanizeParams.ts) control session metadata with misleading origin/icon/name fields with a redirected remote resource and drive the sequence preview -> mutate controlled state -> confirm so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/humanizeParams.ts` / `visibleParams`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: session metadata with misleading origin/icon/name fields; with a redirected remote resource
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
