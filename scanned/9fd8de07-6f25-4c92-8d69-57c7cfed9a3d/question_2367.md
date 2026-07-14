# Q2367: walletconnect via useWalletConnect 2367

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `useWalletConnect` (packages/gui/src/hooks/useWalletConnect.ts) control previously granted bypass permission combined with profile switch after a profile switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnect.ts` / `useWalletConnect`
- Entrypoint: pairing URI/import flow
- Attacker controls: previously granted bypass permission combined with profile switch; after a profile switch
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
