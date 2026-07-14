# Q3030: offers via if 3030

## Question
Can an unprivileged attacker entering through the crafted offer file import in `if` (packages/gui/src/components/offers/OfferSummary.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with a duplicate identifier and drive the sequence open notification -> resolve details -> execute so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferSummary.tsx` / `if`
- Entrypoint: crafted offer file import
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with a duplicate identifier
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
