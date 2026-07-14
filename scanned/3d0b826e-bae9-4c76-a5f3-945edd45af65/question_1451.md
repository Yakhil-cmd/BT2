# Q1451: offers via extractCrCatData 1451

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `extractCrCatData` (packages/gui/src/util/offerToOfferBuilderData.ts) control remote offer URL response that changes between preview and acceptance during a pending modal confirmation and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/offerToOfferBuilderData.ts` / `extractCrCatData`
- Entrypoint: incoming offer notification open flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; during a pending modal confirmation
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
