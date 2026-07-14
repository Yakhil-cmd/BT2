# Q1158: offers via if 1158

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `if` (packages/gui/src/components/offers/OfferShareDialog.tsx) control royalty and fee fields near zero/rounding limits with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferShareDialog.tsx` / `if`
- Entrypoint: offer builder submit flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with a stale Redux cache
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
