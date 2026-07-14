# Q306: walletconnect via getDappCommandSchema 306

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `getDappCommandSchema` (packages/gui/src/electron/commands/getDappCommandSchema.ts) control session metadata with misleading origin/icon/name fields with a delayed metadata fetch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/getDappCommandSchema.ts` / `getDappCommandSchema`
- Entrypoint: pairing URI/import flow
- Attacker controls: session metadata with misleading origin/icon/name fields; with a delayed metadata fetch
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
