# Q782: offers via RoyaltyCalculationRoyaltyAsset 782

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `RoyaltyCalculationRoyaltyAsset` (packages/api/src/@types/RoyaltyCalculationRoyaltyAsset.ts) control offer bytes whose summary differs from displayed builder data with a stale Redux cache and drive the sequence preview -> mutate controlled state -> confirm so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/api/src/@types/RoyaltyCalculationRoyaltyAsset.ts` / `RoyaltyCalculationRoyaltyAsset`
- Entrypoint: incoming offer notification open flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; with a stale Redux cache
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
