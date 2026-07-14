# Q570: rpc-state via parseProgressUpdate 570

## Question
Can an unprivileged attacker entering through the RTK query cache update in `parseProgressUpdate` (packages/api/src/services/PlotterService.ts) control subscription event for a different wallet/fingerprint with a redirected remote resource and drive the sequence connect -> approve -> switch context -> execute so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/PlotterService.ts` / `parseProgressUpdate`
- Entrypoint: RTK query cache update
- Attacker controls: subscription event for a different wallet/fingerprint; with a redirected remote resource
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
