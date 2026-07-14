# Q2368: walletconnect via useWalletConnectPreferences 2368

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `useWalletConnectPreferences` (packages/gui/src/hooks/useWalletConnectPreferences.ts) control session metadata with misleading origin/icon/name fields through a batch of rapid user-accessible actions and drive the sequence download or render content -> trigger linked wallet action so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnectPreferences.ts` / `useWalletConnectPreferences`
- Entrypoint: WalletConnect session proposal
- Attacker controls: session metadata with misleading origin/icon/name fields; through a batch of rapid user-accessible actions
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
