# Q230: offers via OfferMojoAmount 230

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferMojoAmount` (packages/gui/src/components/offers/OfferSummaryRow.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with conflicting localStorage preferences and drive the sequence connect -> approve -> switch context -> execute so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferSummaryRow.tsx` / `OfferMojoAmount`
- Entrypoint: incoming offer notification open flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with conflicting localStorage preferences
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
