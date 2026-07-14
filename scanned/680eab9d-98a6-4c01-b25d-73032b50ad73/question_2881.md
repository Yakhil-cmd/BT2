# Q2881: walletconnect via handleMessage 2881

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `handleMessage` (packages/gui/src/electron/api/sendCommand.ts) control batched sign/spend command sequence after a profile switch and drive the sequence select -> edit backing object -> submit so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/api/sendCommand.ts` / `handleMessage`
- Entrypoint: stored dapp permission reload
- Attacker controls: batched sign/spend command sequence; after a profile switch
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
