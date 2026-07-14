# Q153: nft-metadata via NFTBurnDialog 153

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTBurnDialog` (packages/gui/src/components/nfts/NFTBurnDialog.tsx) control filename and MIME/type mismatch during download with a cached permission entry and drive the sequence select -> edit backing object -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTBurnDialog.tsx` / `NFTBurnDialog`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with a cached permission entry
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
