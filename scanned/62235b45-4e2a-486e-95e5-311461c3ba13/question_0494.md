# Q494: offers via allNFTsByOfferSide 494

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `allNFTsByOfferSide` (packages/gui/src/hooks/useResolveNFTOffer.ts) control royalty and fee fields near zero/rounding limits with hidden Unicode characters and drive the sequence open notification -> resolve details -> execute so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/hooks/useResolveNFTOffer.ts` / `allNFTsByOfferSide`
- Entrypoint: offer builder submit flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with hidden Unicode characters
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
