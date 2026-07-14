# Q2136: offers via handleClose 2136

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `handleClose` (packages/gui/src/components/offers2/OfferBuilderViewerDialog.tsx) control royalty and fee fields near zero/rounding limits after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderViewerDialog.tsx` / `handleClose`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: royalty and fee fields near zero/rounding limits; after a network switch
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
