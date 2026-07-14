# Q1921: offers via handleRemove 1921

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `handleRemove` (packages/gui/src/components/offers2/OfferBuilderNFTSection.tsx) control royalty and fee fields near zero/rounding limits through a batch of rapid user-accessible actions and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFTSection.tsx` / `handleRemove`
- Entrypoint: offer builder submit flow
- Attacker controls: royalty and fee fields near zero/rounding limits; through a batch of rapid user-accessible actions
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
