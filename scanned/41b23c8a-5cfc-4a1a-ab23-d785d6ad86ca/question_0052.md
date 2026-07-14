# Q52: offers via OfferBuilderNFTSection 52

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferBuilderNFTSection` (packages/gui/src/components/offers2/OfferBuilderNFTSection.tsx) control remote offer URL response that changes between preview and acceptance after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFTSection.tsx` / `OfferBuilderNFTSection`
- Entrypoint: incoming offer notification open flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; after a network switch
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
