# Q3237: walletconnect via getRequestedCommands 3237

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `getRequestedCommands` (packages/gui/src/electron/utils/addDappBypassPermissions.ts) control batched sign/spend command sequence after a profile switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/addDappBypassPermissions.ts` / `getRequestedCommands`
- Entrypoint: WalletConnect session proposal
- Attacker controls: batched sign/spend command sequence; after a profile switch
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
