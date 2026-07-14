# Q606: nft-metadata via StyledSyncingFooter 606

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `StyledSyncingFooter` (packages/gui/src/components/plotNFT/PlotExternalNFTCard.tsx) control metadata URI list with mixed schemes and redirects after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotExternalNFTCard.tsx` / `StyledSyncingFooter`
- Entrypoint: on-demand NFT data provider
- Attacker controls: metadata URI list with mixed schemes and redirects; after a network switch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
