# Q1140: offers via handleClose 1140

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `handleClose` (packages/gui/src/components/offers/OfferDataDialog.tsx) control offer bytes whose summary differs from displayed builder data after a failed RPC response and drive the sequence load persisted state -> render approval -> execute command so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferDataDialog.tsx` / `handleClose`
- Entrypoint: incoming offer notification open flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; after a failed RPC response
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
