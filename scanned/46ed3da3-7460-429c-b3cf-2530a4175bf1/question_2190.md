# Q2190: walletconnect via nextParams 2190

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `nextParams` (packages/gui/src/electron/commands/parseDappParams.ts) control previously granted bypass permission combined with profile switch through a batch of rapid user-accessible actions and drive the sequence load persisted state -> render approval -> execute command so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/parseDappParams.ts` / `nextParams`
- Entrypoint: dapp command permission prompt
- Attacker controls: previously granted bypass permission combined with profile switch; through a batch of rapid user-accessible actions
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
