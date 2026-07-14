# Q2071: offers via OfferAsset 2071

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferAsset` (packages/gui/src/components/offers/OfferAsset.ts) control offer bytes whose summary differs from displayed builder data through a batch of rapid user-accessible actions and drive the sequence download or render content -> trigger linked wallet action so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferAsset.ts` / `OfferAsset`
- Entrypoint: incoming offer notification open flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; through a batch of rapid user-accessible actions
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
