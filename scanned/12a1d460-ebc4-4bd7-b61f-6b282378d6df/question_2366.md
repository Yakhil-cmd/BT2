# Q2366: walletconnect via useWalletConnect 2366

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `useWalletConnect` (packages/gui/src/hooks/useWalletConnect.ts) control previously granted bypass permission combined with profile switch after a profile switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnect.ts` / `useWalletConnect`
- Entrypoint: dapp command permission prompt
- Attacker controls: previously granted bypass permission combined with profile switch; after a profile switch
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
