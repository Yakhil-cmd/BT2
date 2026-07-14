# Q979: offers via OfferBuilderImport 979

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `OfferBuilderImport` (packages/gui/src/components/offers2/OfferBuilderImport.tsx) control remote offer URL response that changes between preview and acceptance after a network switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderImport.tsx` / `OfferBuilderImport`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; after a network switch
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
