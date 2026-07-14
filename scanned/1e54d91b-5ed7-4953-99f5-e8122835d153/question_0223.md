# Q223: offers via OfferRowData 223

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferRowData` (packages/gui/src/components/offers/OfferRowData.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferRowData.tsx` / `OfferRowData`
- Entrypoint: incoming offer notification open flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with precision-boundary values
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
