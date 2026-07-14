# Q1102: nft-metadata via unsubscribeDownloadProgress 1102

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `unsubscribeDownloadProgress` (packages/gui/src/components/nfts/NFTProgressBar.tsx) control objectionable-content flags and hidden NFT state with precision-boundary values and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTProgressBar.tsx` / `unsubscribeDownloadProgress`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; with precision-boundary values
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
