# Q3784: offers via OfferBuilderNFTProvenance 3784

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `OfferBuilderNFTProvenance` (packages/gui/src/components/offers2/OfferBuilderNFTProvenance.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFTProvenance.tsx` / `OfferBuilderNFTProvenance`
- Entrypoint: incoming offer notification open flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with hidden Unicode characters
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
