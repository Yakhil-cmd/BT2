# Q2544: offers via useOfferInfo 2544

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `useOfferInfo` (packages/gui/src/hooks/useOfferInfo.ts) control remote offer URL response that changes between preview and acceptance after a failed RPC response and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/hooks/useOfferInfo.ts` / `useOfferInfo`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; after a failed RPC response
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
