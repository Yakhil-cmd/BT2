# Q320: walletconnect via isSpendCommand 320

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `isSpendCommand` (packages/gui/src/electron/commands/isSpendCommand.ts) control method name and params with casing or namespace ambiguity after a profile switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isSpendCommand.ts` / `isSpendCommand`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: method name and params with casing or namespace ambiguity; after a profile switch
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
