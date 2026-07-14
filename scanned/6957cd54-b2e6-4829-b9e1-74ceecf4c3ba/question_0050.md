# Q50: offers via OfferBuilderNFTRoyalties 50

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferBuilderNFTRoyalties` (packages/gui/src/components/offers2/OfferBuilderNFTRoyalties.tsx) control offer bytes whose summary differs from displayed builder data with reordered RPC events and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFTRoyalties.tsx` / `OfferBuilderNFTRoyalties`
- Entrypoint: incoming offer notification open flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; with reordered RPC events
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
