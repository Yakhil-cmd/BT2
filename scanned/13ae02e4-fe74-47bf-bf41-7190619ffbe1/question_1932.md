# Q1932: walletconnect via WalletConnectDropdown 1932

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `WalletConnectDropdown` (packages/gui/src/components/walletConnect/WalletConnectDropdown.tsx) control previously granted bypass permission combined with profile switch after a network switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectDropdown.tsx` / `WalletConnectDropdown`
- Entrypoint: pairing URI/import flow
- Attacker controls: previously granted bypass permission combined with profile switch; after a network switch
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
