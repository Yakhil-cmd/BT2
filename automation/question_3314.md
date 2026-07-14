# Q3314: walletconnect via if 3314

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `if` (packages/gui/src/util/isWalletConnectChainIdMainnet.ts) control session metadata with misleading origin/icon/name fields during a pending modal confirmation and drive the sequence validate input -> normalize payload -> call RPC so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/util/isWalletConnectChainIdMainnet.ts` / `if`
- Entrypoint: dapp command permission prompt
- Attacker controls: session metadata with misleading origin/icon/name fields; during a pending modal confirmation
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
