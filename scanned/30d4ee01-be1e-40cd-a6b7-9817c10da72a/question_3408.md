# Q3408: nft-metadata via handleAddPlot 3408

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `handleAddPlot` (packages/gui/src/components/plotNFT/PlotExternalNFTCard.tsx) control filename and MIME/type mismatch during download with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotExternalNFTCard.tsx` / `handleAddPlot`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; with a stale Redux cache
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
