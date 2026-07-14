# Q501: walletconnect via useWalletConnectPreferences 501

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `useWalletConnectPreferences` (packages/gui/src/hooks/useWalletConnectPreferences.ts) control batched sign/spend command sequence after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnectPreferences.ts` / `useWalletConnectPreferences`
- Entrypoint: pairing URI/import flow
- Attacker controls: batched sign/spend command sequence; after a network switch
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
