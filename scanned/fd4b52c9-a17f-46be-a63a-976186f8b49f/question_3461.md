# Q3461: nft-metadata via useFilteredNFTs 3461

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useFilteredNFTs` (packages/gui/src/hooks/useFilteredNFTs.ts) control filename and MIME/type mismatch during download during a pending modal confirmation and drive the sequence import -> parse -> preview -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useFilteredNFTs.ts` / `useFilteredNFTs`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; during a pending modal confirmation
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
