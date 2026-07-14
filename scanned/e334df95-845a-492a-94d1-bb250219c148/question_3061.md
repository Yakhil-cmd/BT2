# Q3061: offers via handleSelection 3061

## Question
Can an unprivileged attacker entering through the crafted offer file import in `handleSelection` (packages/gui/src/components/offers2/OfferBuilderTokenSelector.tsx) control offer bytes whose summary differs from displayed builder data with precision-boundary values and drive the sequence preview -> mutate controlled state -> confirm so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderTokenSelector.tsx` / `handleSelection`
- Entrypoint: crafted offer file import
- Attacker controls: offer bytes whose summary differs from displayed builder data; with precision-boundary values
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
