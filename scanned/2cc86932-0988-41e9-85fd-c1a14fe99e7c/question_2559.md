# Q2559: offers via createOfferForIdsToOfferBuilderData 2559

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `createOfferForIdsToOfferBuilderData` (packages/gui/src/util/createOfferForIdsToOfferBuilderData.ts) control royalty and fee fields near zero/rounding limits with reordered RPC events and drive the sequence import -> parse -> preview -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/createOfferForIdsToOfferBuilderData.ts` / `createOfferForIdsToOfferBuilderData`
- Entrypoint: incoming offer notification open flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with reordered RPC events
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
