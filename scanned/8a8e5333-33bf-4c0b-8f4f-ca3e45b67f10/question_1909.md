# Q1909: offers via parseOfferSummary 1909

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `parseOfferSummary` (packages/gui/src/components/offers/OfferImport.tsx) control conflicting offer IDs and secure-cancel flags with a cached permission entry and drive the sequence fetch -> cache -> refresh -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferImport.tsx` / `parseOfferSummary`
- Entrypoint: incoming offer notification open flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; with a cached permission entry
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
