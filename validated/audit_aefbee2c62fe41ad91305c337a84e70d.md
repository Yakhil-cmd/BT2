### Title
`NFTMoveToProfileAction` Does Not Clear `gallery-selected-nfts` Selection State After Successful DID Move — (File: `packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx`)

### Summary

`NFTMoveToProfileAction.handleSubmit` does not call `setSelectedNFTIds([])` on the normal success path, leaving stale NFT IDs in the `gallery-selected-nfts` localStorage key after a successful "Move to Profile" operation. Every other NFT-modifying action (Transfer, Burn) clears this selection on success. The stale selection persists across the session and causes the gallery to display those NFTs as still-selected, enabling a user to unknowingly trigger a second bulk action (Transfer, Burn, Create Offer) on NFTs they already processed.

### Finding Description

In `NFTMoveToProfileAction.handleSubmit`, the three outcome branches are:

1. `Array.isArray(response)` — calls `setSelectedNFTIds([])` ✓ (but the code itself notes this branch is **never triggered**)
2. `else if (!error)` — the **normal success path** — does **not** call `setSelectedNFTIds([])` ✗
3. `else` (error) — does not clear (correct) [1](#0-0) 

The comment at line 146 explicitly acknowledges the only branch that clears the selection is dead code: [2](#0-1) 

By contrast, `NFTTransferContextualAction.handleComplete` and `NFTBurnDialog.handleSubmit` both call `setSelectedNFTIds([])` on success: [3](#0-2) [4](#0-3) 

The `gallery-selected-nfts` key is stored in `localStorage` (not scoped to a fingerprint or session), so the stale IDs survive page reloads: [5](#0-4) 

In `NFTGallery`, `selectedVisibleNFTs` is computed by filtering the live NFT list against the persisted IDs. After a "Move to Profile" succeeds, the moved NFTs remain visible in "All NFTs" view (they are still owned by the same user, just under a different DID wallet), so they continue to match the stale IDs and appear selected: [6](#0-5) 

### Impact Explanation

After a successful "Move to Profile", the NFTs remain visually selected in the gallery. The `SelectedActionsDialog` continues to show them as part of the active multi-selection. If the user then triggers "Transfer NFT", "Burn", or "Create Offer" on what they believe is a fresh or empty selection, those already-processed NFTs are included in the operation. This can result in:

- **Unintended NFT transfer** to an attacker-controlled or wrong address
- **Unintended NFT burn** (permanent, irreversible loss)
- **Unintended offer creation** locking the NFT at an unintended price

This matches the allowed High impact: *"Corruption or unsafe trust of NFT state that causes a user to approve, sign, send, or burn the wrong asset."*

### Likelihood Explanation

The "Move to Profile" workflow is a common operation for users organizing their NFT collection. The stale selection is invisible unless the user actively inspects the gallery after the dialog closes. The `SelectedActionsDialog` appears automatically when any NFTs are selected, making it easy to accidentally trigger a follow-up bulk action. The bug is deterministic and reproducible on every successful "Move to Profile" call.

### Recommendation

Add `setSelectedNFTIds([])` to the normal success branch (`else if (!error)`) in `NFTMoveToProfileAction.handleSubmit`, mirroring the pattern used by `NFTTransferContextualAction` and `NFTBurnDialog`:

```typescript
} else if (!error) {
  setSelectedNFTIds([]);   // ← add this
  openDialog(
    <AlertDialog title={<Trans>NFT Move Pending</Trans>}>
      <Trans>The NFT move transaction has been successfully submitted to the blockchain.</Trans>
    </AlertDialog>,
  );
}
```

Additionally, remove or fix the dead `Array.isArray(response)` branch, which already has the correct call but is never reached.

### Proof of Concept

1. Open the NFT gallery and enable multi-select mode.
2. Select one or more NFTs.
3. Open the context menu → **Move to Profile** → choose a DID profile → click **Move**.
4. Observe the success dialog: *"The NFT move transaction has been successfully submitted to the blockchain."*
5. Close the dialog. The moved NFTs remain visually selected in the gallery (highlighted cards, `SelectedActionsDialog` still visible).
6. Without re-selecting anything, click **Transfer NFT** in the `SelectedActionsDialog`.
7. The transfer dialog pre-populates with the already-moved NFTs. Confirming the transfer sends a second, unintended `nft_transfer_nft` RPC call for those NFTs. [7](#0-6)

### Citations

**File:** packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx (L138-189)
```typescript
    try {
      const { error, data: response } = await setNFTDID({
        walletId: nfts[0].walletId,
        nftCoinIds: nfts.map((nft) => removeHexPrefix(nft.nftCoinId)),
        did: destinationDID,
        fee: feeInMojos,
      });

      // TODO: this condition is never triggered, since the mutation never returns array
      if (Array.isArray(response)) {
        const successTransfers = response.filter((r: any) => r?.success === true);
        const failedTransfers = response.filter((r: any) => r?.success !== true);
        setSelectedNFTIds([]);
        openDialog(
          <AlertDialog title={<Trans>NFT Move Pending</Trans>}>
            <ErrorTextWrapper>
              <div>
                <Trans
                  id="{count} transactions have been successfully submitted to the blockchain."
                  values={{ count: successTransfers.length }}
                />
              </div>
              <div>
                {failedTransfers.length ? (
                  <Trans id="{count} NFTs failed to move." values={{ count: failedTransfers.length }} />
                ) : null}
              </div>
            </ErrorTextWrapper>
          </AlertDialog>,
        );
      } else if (!error) {
        openDialog(
          <AlertDialog title={<Trans>NFT Move Pending</Trans>}>
            <Trans>The NFT move transaction has been successfully submitted to the blockchain.</Trans>
          </AlertDialog>,
        );
      } else {
        const err = error?.message || 'Unknown error';
        openDialog(
          <AlertDialog title={<Trans>NFT Move Failed</Trans>}>
            <Trans>The NFT move failed: {err}</Trans>
          </AlertDialog>,
        );
      }
    } catch (error) {
      errorDialog(error);
    } finally {
      if (onComplete) {
        onComplete();
      }
    }
  }
```

**File:** packages/gui/src/components/nfts/NFTContextualActions.tsx (L169-177)
```typescript
  function handleComplete(result?: NFTTransferResult) {
    if (result) {
      if (!result.error) {
        setSelectedNFTIds([]);
        openDialog(
          <AlertDialog title={<Trans>NFT Transfer Pending</Trans>}>
            <Trans>The NFT transfer transaction has been successfully submitted to the blockchain.</Trans>
          </AlertDialog>,
        );
```

**File:** packages/gui/src/components/nfts/NFTBurnDialog.tsx (L107-110)
```typescript

      setSelectedNFTIds([]);

      onClose();
```

**File:** packages/api-react/src/hooks/useLocalStorage.ts (L54-55)
```typescript
        window.localStorage.setItem(key, newStoredValue);
        eventEmitter.emit('storage', { key, newValue } as EventEmitterValue);
```

**File:** packages/gui/src/components/nfts/gallery/NFTGallery.tsx (L151-156)
```typescript
  const [selectedNFTIds, setSelectedNFTIds] = useLocalStorage<string[]>('gallery-selected-nfts', []);

  const selectedVisibleNFTs = useMemo(
    () => nfts.filter((nft: NFTInfo) => selectedNFTIds.includes(nft.$nftId)),
    [nfts, selectedNFTIds],
  );
```
