# Q2316: nft-metadata via cleanup 2316

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `cleanup` (packages/gui/src/electron/utils/fetchJSON.ts) control filename and MIME/type mismatch during download with a redirected remote resource and drive the sequence open notification -> resolve details -> execute so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/utils/fetchJSON.ts` / `cleanup`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; with a redirected remote resource
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
