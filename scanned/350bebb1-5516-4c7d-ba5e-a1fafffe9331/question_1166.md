# Q1166: offers via OfferViewerTitle 1166

## Question
Can an unprivileged attacker entering through the crafted offer file import in `OfferViewerTitle` (packages/gui/src/components/offers/OfferViewerTitle.tsx) control remote offer URL response that changes between preview and acceptance with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferViewerTitle.tsx` / `OfferViewerTitle`
- Entrypoint: crafted offer file import
- Attacker controls: remote offer URL response that changes between preview and acceptance; with a stale Redux cache
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
