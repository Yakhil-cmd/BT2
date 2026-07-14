# Q2075: offers via OfferDataDialog 2075

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferDataDialog` (packages/gui/src/components/offers/OfferDataDialog.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferDataDialog.tsx` / `OfferDataDialog`
- Entrypoint: incoming offer notification open flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; after a network switch
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
