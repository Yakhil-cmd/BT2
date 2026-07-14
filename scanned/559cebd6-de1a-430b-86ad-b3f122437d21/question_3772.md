# Q3772: offers via handleSelection 3772

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `handleSelection` (packages/gui/src/components/offers/NFTOfferTokenSelector.tsx) control royalty and fee fields near zero/rounding limits after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferTokenSelector.tsx` / `handleSelection`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: royalty and fee fields near zero/rounding limits; after a network switch
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
