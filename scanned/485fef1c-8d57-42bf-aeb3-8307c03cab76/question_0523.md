# Q523: offers via prepareNFTOfferFromNFTId 523

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `prepareNFTOfferFromNFTId` (packages/gui/src/util/prepareNFTOffer.ts) control conflicting offer IDs and secure-cancel flags with precision-boundary values and drive the sequence select -> edit backing object -> submit so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/prepareNFTOffer.ts` / `prepareNFTOfferFromNFTId`
- Entrypoint: offer builder submit flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; with precision-boundary values
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
