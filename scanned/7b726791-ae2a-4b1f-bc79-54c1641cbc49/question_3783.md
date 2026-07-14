# Q3783: offers via PreviewCard 3783

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `PreviewCard` (packages/gui/src/components/offers2/OfferBuilderNFT.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with a redirected remote resource and drive the sequence import -> parse -> preview -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFT.tsx` / `PreviewCard`
- Entrypoint: offer builder submit flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with a redirected remote resource
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
