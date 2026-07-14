# Q1516: offers via nfts 1516

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `nfts` (packages/gui/src/components/offers2/utils/createDefaultValues.ts) control remote offer URL response that changes between preview and acceptance with case-normalized identifiers and drive the sequence preview -> mutate controlled state -> confirm so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/utils/createDefaultValues.ts` / `nfts`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; with case-normalized identifiers
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
