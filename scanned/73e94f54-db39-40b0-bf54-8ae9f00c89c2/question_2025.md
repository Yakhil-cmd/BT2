# Q2025: nft-metadata via NFTCreateOfferContextualAction 2025

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTCreateOfferContextualAction` (packages/gui/src/components/nfts/NFTContextualActions.tsx) control objectionable-content flags and hidden NFT state after a profile switch and drive the sequence open notification -> resolve details -> execute so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTContextualActions.tsx` / `NFTCreateOfferContextualAction`
- Entrypoint: NFT preview dialog
- Attacker controls: objectionable-content flags and hidden NFT state; after a profile switch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
