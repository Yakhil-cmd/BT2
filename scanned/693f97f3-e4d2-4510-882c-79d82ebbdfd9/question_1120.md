# Q1120: nft-metadata via NFTGallery 1120

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTGallery` (packages/gui/src/components/nfts/gallery/NFTGallery.tsx) control filename and MIME/type mismatch during download through a batch of rapid user-accessible actions and drive the sequence validate input -> normalize payload -> call RPC so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGallery.tsx` / `NFTGallery`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; through a batch of rapid user-accessible actions
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
