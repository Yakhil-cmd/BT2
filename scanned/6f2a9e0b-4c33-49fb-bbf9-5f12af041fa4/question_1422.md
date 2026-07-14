# Q1422: nft-metadata via useNFTMinterDID 1422

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `useNFTMinterDID` (packages/gui/src/hooks/useNFTMinterDID.ts) control filename and MIME/type mismatch during download with conflicting localStorage preferences and drive the sequence select -> edit backing object -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTMinterDID.ts` / `useNFTMinterDID`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with conflicting localStorage preferences
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
