# Q25: nft-metadata via useNFTData 25

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `useNFTData` (packages/gui/src/components/nfts/provider/hooks/useNFTData.ts) control filename and MIME/type mismatch during download with a cached permission entry and drive the sequence import -> parse -> preview -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/hooks/useNFTData.ts` / `useNFTData`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: filename and MIME/type mismatch during download; with a cached permission entry
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
