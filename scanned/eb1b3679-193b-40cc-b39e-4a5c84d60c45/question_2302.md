# Q2302: walletconnect via addDappBypassPermissions 2302

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `addDappBypassPermissions` (packages/gui/src/electron/utils/addDappBypassPermissions.ts) control session metadata with misleading origin/icon/name fields through a batch of rapid user-accessible actions and drive the sequence import -> parse -> preview -> submit so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/addDappBypassPermissions.ts` / `addDappBypassPermissions`
- Entrypoint: WalletConnect session proposal
- Attacker controls: session metadata with misleading origin/icon/name fields; through a batch of rapid user-accessible actions
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
