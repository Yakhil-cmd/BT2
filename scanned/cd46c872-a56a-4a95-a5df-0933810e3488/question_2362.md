# Q2362: offers via checkNFTOwnership 2362

## Question
Can an unprivileged attacker entering through the crafted offer file import in `checkNFTOwnership` (packages/gui/src/hooks/useResolveNFTOffer.ts) control remote offer URL response that changes between preview and acceptance after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/hooks/useResolveNFTOffer.ts` / `checkNFTOwnership`
- Entrypoint: crafted offer file import
- Attacker controls: remote offer URL response that changes between preview and acceptance; after a network switch
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
