# Q966: offers via NFTOfferExchangeType 966

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `NFTOfferExchangeType` (packages/gui/src/components/offers/NFTOfferExchangeType.ts) control NFT/CAT identifiers with duplicate or ambiguous entries after a profile switch and drive the sequence select -> edit backing object -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferExchangeType.ts` / `NFTOfferExchangeType`
- Entrypoint: incoming offer notification open flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; after a profile switch
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
