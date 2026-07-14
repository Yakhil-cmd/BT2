# Q1836: nft-metadata via useHideObjectionableContent 1836

## Question
Can an unprivileged attacker entering through the external NFT link open action in `useHideObjectionableContent` (packages/gui/src/hooks/useHideObjectionableContent.ts) control filename and MIME/type mismatch during download after canceling and reopening the dialog and drive the sequence load persisted state -> render approval -> execute command so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useHideObjectionableContent.ts` / `useHideObjectionableContent`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; after canceling and reopening the dialog
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
