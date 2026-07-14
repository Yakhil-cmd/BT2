# Q2849: offers via OfferBuilderNFT 2849

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferBuilderNFT` (packages/gui/src/components/offers2/OfferBuilderNFT.tsx) control remote offer URL response that changes between preview and acceptance with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFT.tsx` / `OfferBuilderNFT`
- Entrypoint: incoming offer notification open flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; with case-normalized identifiers
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
