# Q3303: walletconnect via setEnabled 3303

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `setEnabled` (packages/gui/src/hooks/useWalletConnectPreferences.ts) control method name and params with casing or namespace ambiguity after a profile switch and drive the sequence select -> edit backing object -> submit so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnectPreferences.ts` / `setEnabled`
- Entrypoint: WalletConnect session proposal
- Attacker controls: method name and params with casing or namespace ambiguity; after a profile switch
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
