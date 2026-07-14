# Q229: offers via OfferSummary 229

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `OfferSummary` (packages/gui/src/components/offers/OfferSummary.tsx) control conflicting offer IDs and secure-cancel flags with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferSummary.tsx` / `OfferSummary`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; with precision-boundary values
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
