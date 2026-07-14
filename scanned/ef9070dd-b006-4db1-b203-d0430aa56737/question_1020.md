# Q1020: walletconnect via if 1020

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `if` (packages/gui/src/electron/commands/parseCommandId.ts) control session metadata with misleading origin/icon/name fields with a stale Redux cache and drive the sequence preview -> mutate controlled state -> confirm so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/parseCommandId.ts` / `if`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: session metadata with misleading origin/icon/name fields; with a stale Redux cache
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
