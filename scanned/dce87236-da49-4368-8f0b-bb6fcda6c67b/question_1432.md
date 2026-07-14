# Q1432: walletconnect via if 1432

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `if` (packages/gui/src/hooks/useWalletConnect.ts) control previously granted bypass permission combined with profile switch through a batch of rapid user-accessible actions and drive the sequence connect -> approve -> switch context -> execute so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnect.ts` / `if`
- Entrypoint: pairing URI/import flow
- Attacker controls: previously granted bypass permission combined with profile switch; through a batch of rapid user-accessible actions
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
