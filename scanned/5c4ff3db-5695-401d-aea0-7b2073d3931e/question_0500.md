# Q500: walletconnect via useWalletConnectPreferences 500

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `useWalletConnectPreferences` (packages/gui/src/hooks/useWalletConnectPreferences.ts) control batched sign/spend command sequence after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnectPreferences.ts` / `useWalletConnectPreferences`
- Entrypoint: dapp command permission prompt
- Attacker controls: batched sign/spend command sequence; after a network switch
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
