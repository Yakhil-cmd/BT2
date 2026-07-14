# Q1908: offers via parseOfferSummary 1908

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `parseOfferSummary` (packages/gui/src/components/offers/OfferImport.tsx) control royalty and fee fields near zero/rounding limits with a cached permission entry and drive the sequence fetch -> cache -> refresh -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferImport.tsx` / `parseOfferSummary`
- Entrypoint: offer builder submit flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with a cached permission entry
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
