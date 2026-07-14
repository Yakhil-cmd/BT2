# Q1056: nft-metadata via launcherIdToNFTId 1056

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `launcherIdToNFTId` (packages/gui/src/util/nfts.ts) control filename and MIME/type mismatch during download through a batch of rapid user-accessible actions and drive the sequence load persisted state -> render approval -> execute command so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/nfts.ts` / `launcherIdToNFTId`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; through a batch of rapid user-accessible actions
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
