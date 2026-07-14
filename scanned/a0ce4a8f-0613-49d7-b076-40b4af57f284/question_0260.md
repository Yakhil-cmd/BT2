# Q260: offers via OfferBuilderTokensSection 260

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `OfferBuilderTokensSection` (packages/gui/src/components/offers2/OfferBuilderTokensSection.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with hidden Unicode characters and drive the sequence select -> edit backing object -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderTokensSection.tsx` / `OfferBuilderTokensSection`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with hidden Unicode characters
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
