# Q181: nft-metadata via NFTTransferConfirmationDialog 181

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTTransferConfirmationDialog` (packages/gui/src/components/nfts/NFTTransferConfirmationDialog.tsx) control objectionable-content flags and hidden NFT state after a network switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTTransferConfirmationDialog.tsx` / `NFTTransferConfirmationDialog`
- Entrypoint: NFT preview dialog
- Attacker controls: objectionable-content flags and hidden NFT state; after a network switch
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
