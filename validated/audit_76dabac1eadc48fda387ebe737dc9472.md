### Title
Wrong `walletId` Used for All NFTs in Multi-NFT Bulk Transfer and Profile-Move Operations - (File: `packages/gui/src/components/nfts/NFTTransferAction.tsx`, `packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx`, `packages/api/src/wallets/NFT.ts`)

---

### Summary

Both `NFTTransferAction` and `NFTMoveToProfileAction` accept an array of `NFTInfo` objects (`nfts: NFTInfo[]`) but unconditionally use `nfts[0].walletId` as the `walletId` for every NFT in the batch — including NFTs that belong to different NFT wallets. The underlying RPC layer (`transferNft` / `setNftDid`) then stamps that single first-NFT wallet ID onto every coin in the bulk call. When a user multi-selects NFTs that span more than one NFT wallet (e.g., NFTs from the "Unassigned" inbox wallet and NFTs from a DID-linked profile wallet), the RPC call is issued with the wrong `wallet_id` for the non-first NFTs, causing those NFTs to be operated on under an incorrect wallet context.

---

### Finding Description

**Analog to the external bug:** In the Float Capital bug, `latestMarket` (a global/first-initialized value) was used instead of the per-call `marketIndex` parameter, causing all operations to be applied to the wrong market. Here, `nfts[0].walletId` (the wallet of the first selected NFT) is used as a fixed global substitute for the per-NFT `walletId`, causing all NFTs in a multi-select batch to be submitted under the wrong wallet.

**In `NFTTransferAction.handleSubmit`:**

```ts
await transferNFT({
  walletId: nfts[0].walletId,           // ← always first NFT's wallet
  nftCoinIds: nfts.map((nft) => nft.nftCoinId),  // ← all NFTs
  ...
});
```

This calls `transferNft` in `NFT.ts`, which for bulk (>1 NFT) does:

```ts
nftCoinList: nftCoinIds.map((nftId) => ({ nft_coin_id: nftId, wallet_id: walletId }))
```

Every entry in `nftCoinList` gets `wallet_id: nfts[0].walletId`, even if the NFT at index 1, 2, … belongs to a completely different NFT wallet.

**In `NFTMoveToProfileAction.handleSubmit`:**

```ts
const { error, data: response } = await setNFTDID({
  walletId: nfts[0].walletId,           // ← always first NFT's wallet
  nftCoinIds: nfts.map((nft) => removeHexPrefix(nft.nftCoinId)),
  did: destinationDID,
  ...
});
```

Same pattern: `setNftDid` in `NFT.ts` stamps `nfts[0].walletId` onto every coin in the bulk `nft_set_did_bulk` call.

**How multi-wallet selection is reachable:** The NFT gallery's "All NFTs" view (no profile filter) shows NFTs from all wallets simultaneously. The multi-select mode (`inMultipleSelectionMode`) lets the user select any combination of NFTs regardless of which wallet they belong to. `SelectedActionsDialog` passes the full heterogeneous `selectedVisibleNFTs` array directly to `NFTContextualActions`, which passes it to `NFTTransferAction` / `NFTMoveToProfileAction` without any wallet-homogeneity check.

---

### Impact Explanation

**Critical — unauthorized/incorrect NFT transfer and DID assignment.**

When a user selects NFTs from multiple NFT wallets and triggers "Transfer NFT" or "Move to Profile":

- The RPC call `nft_transfer_bulk` / `nft_set_did_bulk` is issued with `wallet_id` set to the first NFT's wallet for every coin, including coins that belong to other wallets.
- The Chia full node / wallet daemon uses `wallet_id` to locate the coin and authorize the spend. Submitting a coin with the wrong `wallet_id` will either silently fail for those coins (leaving the user believing the transfer succeeded) or — depending on daemon behavior — could cause the spend bundle to be constructed incorrectly.
- For the DID-assignment path, NFTs from a different wallet may have their DID ownership record corrupted or the transaction may be rejected, leaving the NFT in an inconsistent state.
- The user sees a single success dialog regardless, with no indication that some NFTs were processed under the wrong wallet context.

This constitutes a **corruption of NFT ownership/DID state** and **incorrect asset transfer** — matching the "Corruption or spoofing of NFT state that causes a user to approve the wrong asset" High impact category, and potentially Critical if the daemon accepts the mismatched wallet/coin pair and executes a transfer.

---

### Likelihood Explanation

The NFT gallery defaults to "All NFTs" view, which aggregates NFTs from all wallets. Multi-select mode is a first-class UI feature accessible via a toolbar button. Any user with NFTs in more than one NFT wallet (e.g., one DID-linked profile wallet and the unassigned inbox wallet) who uses multi-select and triggers Transfer or Move to Profile will trigger this bug. No special attacker capability is required — this is a normal user workflow.

---

### Recommendation

In both `handleSubmit` functions, group the selected NFTs by their `walletId` and issue one RPC call per wallet group:

```ts
// Group NFTs by walletId
const nftsByWallet = nfts.reduce((acc, nft) => {
  const id = nft.walletId;
  if (!acc[id]) acc[id] = [];
  acc[id].push(nft);
  return acc;
}, {} as Record<number, NFTInfo[]>);

// Issue one call per wallet
for (const [walletId, walletNfts] of Object.entries(nftsByWallet)) {
  await transferNFT({
    walletId: Number(walletId),
    nftCoinIds: walletNfts.map((nft) => nft.nftCoinId),
    targetAddress: destinationLocal,
    fee: feeInMojos,
  }).unwrap();
}
```

Apply the same grouping in `NFTMoveToProfileAction.handleSubmit` for `setNFTDID`.

Alternatively, add a guard in the UI that prevents multi-selecting NFTs from different wallets for bulk operations, or validates wallet homogeneity before submission.

---

### Proof of Concept

1. User has NFTs in two wallets: wallet A (DID-linked profile) and wallet B (unassigned inbox).
2. User opens NFT Gallery → "All NFTs" view.
3. User enables multi-select mode (toolbar button).
4. User selects NFT-1 (walletId=A) and NFT-2 (walletId=B).
5. User clicks "Transfer NFT" → enters a destination address → clicks "Transfer".
6. `NFTTransferAction.handleSubmit` fires with `nfts = [NFT-1, NFT-2]`.
7. `transferNFT({ walletId: NFT-1.walletId (=A), nftCoinIds: [NFT-1.nftCoinId, NFT-2.nftCoinId], ... })` is called.
8. `transferNft` in `NFT.ts` issues `nft_transfer_bulk` with `nftCoinList: [{ nft_coin_id: NFT-1.nftCoinId, wallet_id: A }, { nft_coin_id: NFT-2.nftCoinId, wallet_id: A }]` — NFT-2's correct wallet B is never used.
9. The daemon processes NFT-2 under wallet A's context, which is incorrect. NFT-2's transfer either silently fails or is executed with wrong authorization context.
10. The user sees a single "NFT transfer transaction has been successfully submitted" dialog with no indication of the error.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** packages/gui/src/components/nfts/NFTTransferAction.tsx (L93-98)
```typescript
      await transferNFT({
        walletId: nfts[0].walletId,
        nftCoinIds: nfts.map((nft: NFTInfo) => nft.nftCoinId),
        targetAddress: destinationLocal,
        fee: feeInMojos,
      }).unwrap();
```

**File:** packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx (L139-144)
```typescript
      const { error, data: response } = await setNFTDID({
        walletId: nfts[0].walletId,
        nftCoinIds: nfts.map((nft) => removeHexPrefix(nft.nftCoinId)),
        did: destinationDID,
        fee: feeInMojos,
      });
```

**File:** packages/api/src/wallets/NFT.ts (L161-170)
```typescript
    return this.command<{
      walletId: number[];
      spendBundle: SpendBundle;
      txNum: number;
    }>('nft_transfer_bulk', {
      nftCoinList: nftCoinIds.map((nftId: string) => ({ nft_coin_id: nftId, wallet_id: walletId })),
      targetAddress,
      fee,
      ...extra,
    });
```

**File:** packages/api/src/wallets/NFT.ts (L188-197)
```typescript
    return this.command<{
      walletId: number[];
      spendBundle: SpendBundle;
      txNum: number;
    }>('nft_set_did_bulk', {
      nftCoinList: nftCoinIds.map((nftId: string) => ({ nft_coin_id: nftId, wallet_id: walletId })),
      didId: did,
      fee,
      ...extra,
    });
```

**File:** packages/gui/src/components/nfts/gallery/SelectedActionsDialog.tsx (L64-76)
```typescript
  return (
    <SelectedItemsContainer>
      <TableWrapper>
        <SelectedCountText>{t`${nfts.length} of ${allCount} items selected:`}</SelectedCountText>
        <NFTContextualActions
          selection={{ items: nfts }}
          availableActions={showOrHide > 0 ? menuWithHide : menuWithoutHide}
          isMultiSelect
          showOrHide={showOrHide}
        />
      </TableWrapper>
    </SelectedItemsContainer>
  );
```

**File:** packages/gui/src/components/nfts/gallery/NFTGallery.tsx (L151-156)
```typescript
  const [selectedNFTIds, setSelectedNFTIds] = useLocalStorage<string[]>('gallery-selected-nfts', []);

  const selectedVisibleNFTs = useMemo(
    () => nfts.filter((nft: NFTInfo) => selectedNFTIds.includes(nft.$nftId)),
    [nfts, selectedNFTIds],
  );
```
