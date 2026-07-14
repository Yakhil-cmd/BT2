# Q72: offers via getOfferSummary 72

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `getOfferSummary` (packages/gui/src/electron/api/getOfferSummary.ts) control conflicting offer IDs and secure-cancel flags with a duplicate identifier and drive the sequence preview -> mutate controlled state -> confirm so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/electron/api/getOfferSummary.ts` / `getOfferSummary`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; with a duplicate identifier
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
