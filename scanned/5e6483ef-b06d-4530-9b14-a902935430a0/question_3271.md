# Q3271: walletconnect via toPairPublicRecord 3271

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `toPairPublicRecord` (packages/gui/src/electron/utils/pairSchemas.ts) control batched sign/spend command sequence with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/pairSchemas.ts` / `toPairPublicRecord`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: batched sign/spend command sequence; with precision-boundary values
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
