# Q1182: offers via handleAdd 1182

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `handleAdd` (packages/gui/src/components/offers2/OfferBuilderFeeSection.tsx) control royalty and fee fields near zero/rounding limits with case-normalized identifiers and drive the sequence download or render content -> trigger linked wallet action so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderFeeSection.tsx` / `handleAdd`
- Entrypoint: incoming offer notification open flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with case-normalized identifiers
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
