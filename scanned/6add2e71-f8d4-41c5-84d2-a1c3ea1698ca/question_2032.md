# Q2032: nft-metadata via BlobBg 2032

## Question
Can an unprivileged attacker entering through the external NFT link open action in `BlobBg` (packages/gui/src/components/nfts/NFTPreview.tsx) control filename and MIME/type mismatch during download with precision-boundary values and drive the sequence connect -> approve -> switch context -> execute so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTPreview.tsx` / `BlobBg`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; with precision-boundary values
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
