# Q986: offers via handleAdd 986

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `handleAdd` (packages/gui/src/components/offers2/OfferBuilderNFTSection.tsx) control royalty and fee fields near zero/rounding limits with precision-boundary values and drive the sequence select -> edit backing object -> submit so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFTSection.tsx` / `handleAdd`
- Entrypoint: offer builder submit flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with precision-boundary values
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
