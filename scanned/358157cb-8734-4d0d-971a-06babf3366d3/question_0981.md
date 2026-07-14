# Q981: offers via OfferBuilderNFT 981

## Question
Can an unprivileged attacker entering through the crafted offer file import in `OfferBuilderNFT` (packages/gui/src/components/offers2/OfferBuilderNFT.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with a stale Redux cache and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFT.tsx` / `OfferBuilderNFT`
- Entrypoint: crafted offer file import
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with a stale Redux cache
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
