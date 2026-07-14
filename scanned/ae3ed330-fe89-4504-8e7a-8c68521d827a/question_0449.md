# Q449: nft-metadata via fetchJSON 449

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `fetchJSON` (packages/gui/src/electron/utils/fetchJSON.ts) control filename and MIME/type mismatch during download with reordered RPC events and drive the sequence fetch -> cache -> refresh -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/utils/fetchJSON.ts` / `fetchJSON`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with reordered RPC events
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
