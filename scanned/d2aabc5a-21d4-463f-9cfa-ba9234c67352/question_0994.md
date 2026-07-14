# Q994: walletconnect via methods 994

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `methods` (packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx) control batched sign/spend command sequence with hidden Unicode characters and drive the sequence fetch -> cache -> refresh -> submit so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx` / `methods`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: batched sign/spend command sequence; with hidden Unicode characters
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
