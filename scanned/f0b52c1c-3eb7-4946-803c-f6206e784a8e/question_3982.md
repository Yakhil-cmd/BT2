# Q3982: offers via setExpirationTime 3982

## Question
Can an unprivileged attacker entering through the crafted offer file import in `setExpirationTime` (packages/gui/src/components/offers2/OfferBuilderExpirationSection.tsx) control remote offer URL response that changes between preview and acceptance with a redirected remote resource and drive the sequence fetch -> cache -> refresh -> submit so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderExpirationSection.tsx` / `setExpirationTime`
- Entrypoint: crafted offer file import
- Attacker controls: remote offer URL response that changes between preview and acceptance; with a redirected remote resource
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
