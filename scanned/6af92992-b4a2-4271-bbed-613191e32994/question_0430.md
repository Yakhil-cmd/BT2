# Q430: walletconnect via getTitle 430

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `getTitle` (packages/gui/src/electron/dialogs/Pair/Pair.tsx) control session metadata with misleading origin/icon/name fields with a duplicate identifier and drive the sequence import -> parse -> preview -> submit so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/dialogs/Pair/Pair.tsx` / `getTitle`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: session metadata with misleading origin/icon/name fields; with a duplicate identifier
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
