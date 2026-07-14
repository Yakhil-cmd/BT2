# Q480: walletconnect via useBypassCommands 480

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `useBypassCommands` (packages/gui/src/hooks/useBypassCommands.ts) control session metadata with misleading origin/icon/name fields with a duplicate identifier and drive the sequence fetch -> cache -> refresh -> submit so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useBypassCommands.ts` / `useBypassCommands`
- Entrypoint: dapp command permission prompt
- Attacker controls: session metadata with misleading origin/icon/name fields; with a duplicate identifier
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
