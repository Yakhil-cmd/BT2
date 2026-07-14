# Q1915: offers via PreviewCard 1915

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `PreviewCard` (packages/gui/src/components/offers2/OfferBuilderNFT.tsx) control remote offer URL response that changes between preview and acceptance with a delayed metadata fetch and drive the sequence load persisted state -> render approval -> execute command so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFT.tsx` / `PreviewCard`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; with a delayed metadata fetch
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
