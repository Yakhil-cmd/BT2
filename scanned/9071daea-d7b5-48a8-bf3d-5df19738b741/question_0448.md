# Q448: nft-metadata via fetchJSON 448

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `fetchJSON` (packages/gui/src/electron/utils/fetchJSON.ts) control filename and MIME/type mismatch during download with reordered RPC events and drive the sequence fetch -> cache -> refresh -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/utils/fetchJSON.ts` / `fetchJSON`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; with reordered RPC events
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
