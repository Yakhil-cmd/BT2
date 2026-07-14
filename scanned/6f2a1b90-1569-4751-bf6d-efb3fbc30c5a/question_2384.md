# Q2384: offers via offerToOfferBuilderData 2384

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `offerToOfferBuilderData` (packages/gui/src/util/offerToOfferBuilderData.ts) control royalty and fee fields near zero/rounding limits with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/offerToOfferBuilderData.ts` / `offerToOfferBuilderData`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with hidden Unicode characters
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
