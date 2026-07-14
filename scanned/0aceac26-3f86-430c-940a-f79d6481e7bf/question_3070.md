# Q3070: offers via OfferBuilderViewerDialog 3070

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferBuilderViewerDialog` (packages/gui/src/components/offers2/OfferBuilderViewerDialog.tsx) control royalty and fee fields near zero/rounding limits with precision-boundary values and drive the sequence preview -> mutate controlled state -> confirm so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderViewerDialog.tsx` / `OfferBuilderViewerDialog`
- Entrypoint: incoming offer notification open flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with precision-boundary values
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
