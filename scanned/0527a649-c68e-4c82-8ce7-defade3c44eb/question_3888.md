# Q3888: nft-metadata via renderNFTPreview 3888

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `renderNFTPreview` (packages/gui/src/components/nfts/NFTBurnDialog.tsx) control content hash/status fields that change across fetches during a pending modal confirmation and drive the sequence open notification -> resolve details -> execute so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTBurnDialog.tsx` / `renderNFTPreview`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; during a pending modal confirmation
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
