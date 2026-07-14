# Q39: offers via NFTOfferSummaryRow 39

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `NFTOfferSummaryRow` (packages/gui/src/components/offers/NFTOfferViewer.tsx) control offer bytes whose summary differs from displayed builder data with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferViewer.tsx` / `NFTOfferSummaryRow`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; with hidden Unicode characters
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
