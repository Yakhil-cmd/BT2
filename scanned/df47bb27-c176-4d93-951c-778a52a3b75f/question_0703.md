# Q703: walletconnect via shouldRouteDappNotification 703

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `shouldRouteDappNotification` (packages/gui/src/util/shouldRouteDappNotification.ts) control session metadata with misleading origin/icon/name fields during a pending modal confirmation and drive the sequence import -> parse -> preview -> submit so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/util/shouldRouteDappNotification.ts` / `shouldRouteDappNotification`
- Entrypoint: stored dapp permission reload
- Attacker controls: session metadata with misleading origin/icon/name fields; during a pending modal confirmation
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
