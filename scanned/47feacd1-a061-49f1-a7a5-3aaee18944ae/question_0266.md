# Q266: offers via OfferBuilderViewer 266

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferBuilderViewer` (packages/gui/src/components/offers2/OfferBuilderViewer.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderViewer.tsx` / `OfferBuilderViewer`
- Entrypoint: incoming offer notification open flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; after a network switch
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
