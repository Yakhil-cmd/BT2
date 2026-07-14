# Q1013: walletconnect via if 1013

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `if` (packages/gui/src/electron/api/sendCommand.ts) control previously granted bypass permission combined with profile switch with hidden Unicode characters and drive the sequence download or render content -> trigger linked wallet action so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/api/sendCommand.ts` / `if`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: previously granted bypass permission combined with profile switch; with hidden Unicode characters
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
