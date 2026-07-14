# Q972: offers via if 972

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `if` (packages/gui/src/components/offers/NFTOfferViewer.tsx) control offer bytes whose summary differs from displayed builder data after a failed RPC response and drive the sequence validate input -> normalize payload -> call RPC so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferViewer.tsx` / `if`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; after a failed RPC response
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
