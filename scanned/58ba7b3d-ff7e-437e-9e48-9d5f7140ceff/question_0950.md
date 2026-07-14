# Q950: nft-metadata via if 950

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `if` (packages/gui/src/components/nfts/NFTMetadata.tsx) control filename and MIME/type mismatch during download with a duplicate identifier and drive the sequence open notification -> resolve details -> execute so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTMetadata.tsx` / `if`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with a duplicate identifier
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
