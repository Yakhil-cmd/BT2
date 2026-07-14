# Q3984: offers via handleAdd 3984

## Question
Can an unprivileged attacker entering through the crafted offer file import in `handleAdd` (packages/gui/src/components/offers2/OfferBuilderFeeSection.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with hidden Unicode characters and drive the sequence open notification -> resolve details -> execute so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderFeeSection.tsx` / `handleAdd`
- Entrypoint: crafted offer file import
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with hidden Unicode characters
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
