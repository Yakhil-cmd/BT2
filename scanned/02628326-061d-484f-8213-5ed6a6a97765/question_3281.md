# Q3281: rpc-state via offerSummaryToWalletDelta 3281

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `offerSummaryToWalletDelta` (packages/gui/src/electron/utils/walletDelta.ts) control subscription event for a different wallet/fingerprint with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/walletDelta.ts` / `offerSummaryToWalletDelta`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with hidden Unicode characters
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
