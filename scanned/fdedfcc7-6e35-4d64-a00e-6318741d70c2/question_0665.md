# Q665: nft-metadata via useNFTGalleryScrollPosition 665

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `useNFTGalleryScrollPosition` (packages/gui/src/hooks/useNFTGalleryScrollPosition.ts) control filename and MIME/type mismatch during download after a profile switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTGalleryScrollPosition.ts` / `useNFTGalleryScrollPosition`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; after a profile switch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
