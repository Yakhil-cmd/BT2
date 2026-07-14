# Q2112: offers via OfferBuilderExpirationCountdown 2112

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `OfferBuilderExpirationCountdown` (packages/gui/src/components/offers2/OfferBuilderExpirationCountdown.tsx) control remote offer URL response that changes between preview and acceptance with a duplicate identifier and drive the sequence fetch -> cache -> refresh -> submit so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderExpirationCountdown.tsx` / `OfferBuilderExpirationCountdown`
- Entrypoint: offer builder submit flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; with a duplicate identifier
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
