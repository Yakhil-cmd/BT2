# Q28: nft-metadata via getChangedEventName 28

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `getChangedEventName` (packages/gui/src/components/nfts/provider/hooks/useNFTDataOnDemand.ts) control filename and MIME/type mismatch during download with precision-boundary values and drive the sequence import -> parse -> preview -> submit so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/hooks/useNFTDataOnDemand.ts` / `getChangedEventName`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; with precision-boundary values
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
