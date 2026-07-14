# Q3393: walletconnect via humanizeParams 3393

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `humanizeParams` (packages/gui/src/electron/commands/humanizeParams.ts) control previously granted bypass permission combined with profile switch with hidden Unicode characters and drive the sequence select -> edit backing object -> submit so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/humanizeParams.ts` / `humanizeParams`
- Entrypoint: stored dapp permission reload
- Attacker controls: previously granted bypass permission combined with profile switch; with hidden Unicode characters
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
