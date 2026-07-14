# Q3116: walletconnect via isAllowedCommand 3116

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `isAllowedCommand` (packages/gui/src/electron/commands/isAllowedCommand.ts) control previously granted bypass permission combined with profile switch after a profile switch and drive the sequence open notification -> resolve details -> execute so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isAllowedCommand.ts` / `isAllowedCommand`
- Entrypoint: stored dapp permission reload
- Attacker controls: previously granted bypass permission combined with profile switch; after a profile switch
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
