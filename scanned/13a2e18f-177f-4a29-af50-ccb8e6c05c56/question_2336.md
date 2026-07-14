# Q2336: walletconnect via toPairPublicRecord 2336

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `toPairPublicRecord` (packages/gui/src/electron/utils/pairSchemas.ts) control session metadata with misleading origin/icon/name fields after a network switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/pairSchemas.ts` / `toPairPublicRecord`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: session metadata with misleading origin/icon/name fields; after a network switch
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
