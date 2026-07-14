# Q2378: offers via isDataLayerOfferSummary 2378

## Question
Can an unprivileged attacker entering through the crafted offer file import in `isDataLayerOfferSummary` (packages/gui/src/util/isDataLayerOfferSummary.ts) control offer bytes whose summary differs from displayed builder data with hidden Unicode characters and drive the sequence open notification -> resolve details -> execute so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/isDataLayerOfferSummary.ts` / `isDataLayerOfferSummary`
- Entrypoint: crafted offer file import
- Attacker controls: offer bytes whose summary differs from displayed builder data; with hidden Unicode characters
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
