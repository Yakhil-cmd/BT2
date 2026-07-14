# Q3985: offers via handleAdd 3985

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `handleAdd` (packages/gui/src/components/offers2/OfferBuilderFeeSection.tsx) control royalty and fee fields near zero/rounding limits with hidden Unicode characters and drive the sequence open notification -> resolve details -> execute so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderFeeSection.tsx` / `handleAdd`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with hidden Unicode characters
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
