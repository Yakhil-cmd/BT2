# Q2132: offers via tooltip 2132

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `tooltip` (packages/gui/src/components/offers2/OfferBuilderValue.tsx) control royalty and fee fields near zero/rounding limits with conflicting localStorage preferences and drive the sequence preview -> mutate controlled state -> confirm so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderValue.tsx` / `tooltip`
- Entrypoint: incoming offer notification open flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with conflicting localStorage preferences
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
