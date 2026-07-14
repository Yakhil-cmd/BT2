# Q2087: offers via if 2087

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `if` (packages/gui/src/components/offers/OfferHeader.tsx) control royalty and fee fields near zero/rounding limits with a cached permission entry and drive the sequence connect -> approve -> switch context -> execute so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferHeader.tsx` / `if`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with a cached permission entry
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
