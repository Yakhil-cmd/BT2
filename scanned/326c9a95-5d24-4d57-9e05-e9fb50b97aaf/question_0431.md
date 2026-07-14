# Q431: walletconnect via getTitle 431

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `getTitle` (packages/gui/src/electron/dialogs/Pair/Pair.tsx) control session metadata with misleading origin/icon/name fields with a duplicate identifier and drive the sequence import -> parse -> preview -> submit so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/dialogs/Pair/Pair.tsx` / `getTitle`
- Entrypoint: dapp command permission prompt
- Attacker controls: session metadata with misleading origin/icon/name fields; with a duplicate identifier
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
