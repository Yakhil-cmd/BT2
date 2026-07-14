# Q519: offers via isValidBytes32Hex 519

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `isValidBytes32Hex` (packages/gui/src/util/parseCreateOfferForIdsKey.ts) control remote offer URL response that changes between preview and acceptance after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/parseCreateOfferForIdsKey.ts` / `isValidBytes32Hex`
- Entrypoint: incoming offer notification open flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; after a profile switch
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
