# Q2882: walletconnect via getDappCommandMetadata 2882

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `getDappCommandMetadata` (packages/gui/src/electron/commands/getDappCommandMetadata.ts) control chainId/account/fingerprint mismatch after a profile switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/getDappCommandMetadata.ts` / `getDappCommandMetadata`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: chainId/account/fingerprint mismatch; after a profile switch
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
