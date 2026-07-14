# Q315: walletconnect via isAllowedCommand 315

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `isAllowedCommand` (packages/gui/src/electron/commands/isAllowedCommand.ts) control method name and params with casing or namespace ambiguity after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isAllowedCommand.ts` / `isAllowedCommand`
- Entrypoint: pairing URI/import flow
- Attacker controls: method name and params with casing or namespace ambiguity; after a network switch
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
