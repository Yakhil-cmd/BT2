# Q995: walletconnect via methods 995

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `methods` (packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx) control batched sign/spend command sequence with hidden Unicode characters and drive the sequence fetch -> cache -> refresh -> submit so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx` / `methods`
- Entrypoint: dapp command permission prompt
- Attacker controls: batched sign/spend command sequence; with hidden Unicode characters
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
