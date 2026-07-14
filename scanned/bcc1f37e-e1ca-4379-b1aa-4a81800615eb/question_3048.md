# Q3048: offers via handleNavToSettings 3048

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `handleNavToSettings` (packages/gui/src/components/offers2/OfferBuilderExpirationSection.tsx) control remote offer URL response that changes between preview and acceptance with conflicting localStorage preferences and drive the sequence fetch -> cache -> refresh -> submit so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderExpirationSection.tsx` / `handleNavToSettings`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; with conflicting localStorage preferences
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
