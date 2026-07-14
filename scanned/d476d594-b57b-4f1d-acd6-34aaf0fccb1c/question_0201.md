# Q201: offers via StyledSummaryBox 201

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `StyledSummaryBox` (packages/gui/src/components/offers/OfferAcceptConfirmationDialog.tsx) control royalty and fee fields near zero/rounding limits with a duplicate identifier and drive the sequence import -> parse -> preview -> submit so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferAcceptConfirmationDialog.tsx` / `StyledSummaryBox`
- Entrypoint: incoming offer notification open flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with a duplicate identifier
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
