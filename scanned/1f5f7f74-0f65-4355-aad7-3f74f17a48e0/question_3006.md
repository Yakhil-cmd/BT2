# Q3006: offers via handleSelection 3006

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `handleSelection` (packages/gui/src/components/offers/OfferAssetSelector.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with conflicting localStorage preferences and drive the sequence validate input -> normalize payload -> call RPC so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferAssetSelector.tsx` / `handleSelection`
- Entrypoint: offer builder submit flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with conflicting localStorage preferences
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
