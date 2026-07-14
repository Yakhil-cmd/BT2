# Q3965: offers via OfferSummary 3965

## Question
Can an unprivileged attacker entering through the crafted offer file import in `OfferSummary` (packages/gui/src/components/offers/OfferSummary.tsx) control conflicting offer IDs and secure-cancel flags after canceling and reopening the dialog and drive the sequence validate input -> normalize payload -> call RPC so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferSummary.tsx` / `OfferSummary`
- Entrypoint: crafted offer file import
- Attacker controls: conflicting offer IDs and secure-cancel flags; after canceling and reopening the dialog
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
