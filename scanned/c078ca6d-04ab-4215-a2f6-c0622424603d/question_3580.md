# Q3580: rpc-state via PuzzleDecorator 3580

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `PuzzleDecorator` (packages/api/src/@types/PuzzleDecorator.ts) control subscription event for a different wallet/fingerprint with a cached permission entry and drive the sequence preview -> mutate controlled state -> confirm so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/PuzzleDecorator.ts` / `PuzzleDecorator`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with a cached permission entry
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
