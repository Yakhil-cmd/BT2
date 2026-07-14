# Q518: offers via isValidBytes32Hex 518

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `isValidBytes32Hex` (packages/gui/src/util/parseCreateOfferForIdsKey.ts) control remote offer URL response that changes between preview and acceptance after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/parseCreateOfferForIdsKey.ts` / `isValidBytes32Hex`
- Entrypoint: offer builder submit flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; after a profile switch
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
