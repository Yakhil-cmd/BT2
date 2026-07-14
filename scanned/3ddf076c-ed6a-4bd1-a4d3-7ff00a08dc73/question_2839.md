# Q2839: offers via selected 2839

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `selected` (packages/gui/src/components/offers/NFTOfferTokenSelector.tsx) control remote offer URL response that changes between preview and acceptance with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferTokenSelector.tsx` / `selected`
- Entrypoint: incoming offer notification open flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; with a redirected remote resource
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
