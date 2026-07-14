# Q1256: walletconnect via for 1256

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `for` (packages/gui/src/electron/commands/parseDappParams.ts) control session metadata with misleading origin/icon/name fields with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/parseDappParams.ts` / `for`
- Entrypoint: pairing URI/import flow
- Attacker controls: session metadata with misleading origin/icon/name fields; with precision-boundary values
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
