# Q980: offers via OfferBuilderNFT 980

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `OfferBuilderNFT` (packages/gui/src/components/offers2/OfferBuilderNFT.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with a stale Redux cache and drive the sequence preview -> mutate controlled state -> confirm so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFT.tsx` / `OfferBuilderNFT`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with a stale Redux cache
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
