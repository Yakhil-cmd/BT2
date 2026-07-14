# Q3505: walletconnect via shouldRouteDappNotification 3505

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `shouldRouteDappNotification` (packages/gui/src/util/shouldRouteDappNotification.ts) control method name and params with casing or namespace ambiguity after a network switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/util/shouldRouteDappNotification.ts` / `shouldRouteDappNotification`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: method name and params with casing or namespace ambiguity; after a network switch
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
