# Q2840: offers via NFTOfferSummary 2840

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `NFTOfferSummary` (packages/gui/src/components/offers/NFTOfferViewer.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferViewer.tsx` / `NFTOfferSummary`
- Entrypoint: offer builder submit flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with precision-boundary values
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
