# Q82: walletconnect via isSignCommand 82

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `isSignCommand` (packages/gui/src/electron/commands/isSignCommand.ts) control method name and params with casing or namespace ambiguity with conflicting localStorage preferences and drive the sequence download or render content -> trigger linked wallet action so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isSignCommand.ts` / `isSignCommand`
- Entrypoint: dapp command permission prompt
- Attacker controls: method name and params with casing or namespace ambiguity; with conflicting localStorage preferences
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
