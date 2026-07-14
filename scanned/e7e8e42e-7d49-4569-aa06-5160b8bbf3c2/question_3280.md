# Q3280: rpc-state via offerSummaryToWalletDelta 3280

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `offerSummaryToWalletDelta` (packages/gui/src/electron/utils/walletDelta.ts) control subscription event for a different wallet/fingerprint with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/walletDelta.ts` / `offerSummaryToWalletDelta`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with hidden Unicode characters
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
