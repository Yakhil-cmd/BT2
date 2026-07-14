# Q1596: nft-metadata via if 1596

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `if` (packages/gui/src/hooks/useNFT.ts) control filename and MIME/type mismatch during download after a profile switch and drive the sequence select -> edit backing object -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFT.ts` / `if`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; after a profile switch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
