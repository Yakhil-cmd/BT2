# Q985: offers via rows 985

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `rows` (packages/gui/src/components/offers2/OfferBuilderNFTRoyalties.tsx) control royalty and fee fields near zero/rounding limits with case-normalized identifiers and drive the sequence download or render content -> trigger linked wallet action so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFTRoyalties.tsx` / `rows`
- Entrypoint: incoming offer notification open flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with case-normalized identifiers
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
