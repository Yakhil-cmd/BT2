# Q508: nft-metadata via getNFTFileType 508

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `getNFTFileType` (packages/gui/src/util/getNFTFileType.ts) control filename and MIME/type mismatch during download with a delayed metadata fetch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/getNFTFileType.ts` / `getNFTFileType`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; with a delayed metadata fetch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
