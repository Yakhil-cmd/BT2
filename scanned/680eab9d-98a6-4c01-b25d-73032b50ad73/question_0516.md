# Q516: offers via offerToOfferBuilderData 516

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `offerToOfferBuilderData` (packages/gui/src/util/offerToOfferBuilderData.ts) control remote offer URL response that changes between preview and acceptance with a redirected remote resource and drive the sequence connect -> approve -> switch context -> execute so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/offerToOfferBuilderData.ts` / `offerToOfferBuilderData`
- Entrypoint: incoming offer notification open flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; with a redirected remote resource
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
