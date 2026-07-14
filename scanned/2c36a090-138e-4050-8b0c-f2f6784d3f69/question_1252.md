# Q1252: walletconnect via isDappAllowedCommand 1252

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `isDappAllowedCommand` (packages/gui/src/electron/commands/isDappAllowedCommand.ts) control chainId/account/fingerprint mismatch after canceling and reopening the dialog and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isDappAllowedCommand.ts` / `isDappAllowedCommand`
- Entrypoint: stored dapp permission reload
- Attacker controls: chainId/account/fingerprint mismatch; after canceling and reopening the dialog
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
