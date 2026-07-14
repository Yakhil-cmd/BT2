# Q3248: walletconnect via if 3248

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `if` (packages/gui/src/electron/utils/dispatchPairRequest.ts) control previously granted bypass permission combined with profile switch after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/dispatchPairRequest.ts` / `if`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: previously granted bypass permission combined with profile switch; after a failed RPC response
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
