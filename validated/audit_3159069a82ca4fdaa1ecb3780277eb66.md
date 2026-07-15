### Title
Stray CAT on-chain name trusted without validation, enabling wallet identity spoofing via `handleShow` — (`packages/wallets/src/hooks/useWalletsList.ts`)

### Summary

An attacker who sends a CAT token whose on-chain name matches a well-known token (e.g. "USDS", "Chia") to a victim can cause the victim's GUI to create a new wallet whose display name is the spoofed name but whose `assetId` is the attacker's worthless token. No existing guard prevents this.

---

### Finding Description

In `handleShow`, when the toggled id is a string (i.e. an assetId that has no wallet yet), the code first checks the official `catList`. If the assetId is not found there (it won't be, because the attacker's assetId is novel), it falls through to the `strayCats` branch and uses `strayCat.name` verbatim: [1](#0-0) 

That name is passed directly into `addCATToken`: [2](#0-1) 

`addCATToken` calls `createWalletForExisting` (binding the attacker's `assetId`) and then `setName` (setting the spoofed display name): [3](#0-2) 

The `getStrayCats` RPC response is passed through with no name sanitisation — only `assetId` and `senderPuzzleHash` are normalised: [4](#0-3) 

In Chia, a CAT's metadata (including its name) is set by the token creator and is fully attacker-controlled. There is no check that `strayCat.name` does not collide with any name in `catList` or with the reserved name "Chia".

---

### Impact Explanation

After the victim toggles the stray cat visible, a persistent wallet entry named e.g. "USDS" is created in the GUI backed by the attacker's worthless token. The victim:

- Sees a wallet labelled with a trusted token name whose balance reflects the attacker's airdropped tokens.
- May accept incoming "USDS" payments that are actually the attacker's token (zero real value).
- May send the attacker's token to a counterparty who expects real USDS, causing the counterparty loss.

This satisfies the **High** impact criterion: *unsafe trust of RPC/event state that causes a user to import/display the wrong asset under a spoofed identity*.

---

### Likelihood Explanation

- Sending a CAT airdrop to an arbitrary address is trivially cheap on Chia.
- The victim only needs to toggle the stray cat visible — a natural action when an unexpected token appears in the list.
- No authentication, passphrase, or confirmation dialog stands between the toggle and the wallet creation.
- The stray cat list is polled every 10 seconds, so the entry appears automatically. [5](#0-4) 

---

### Recommendation

Before using `strayCat.name` in `addCATToken`, validate it against the official `catList` names and reject (or sanitise) any name that collides with a known token name or with the reserved string "Chia". A minimal fix in `handleShow`:

```ts
// assign stray cat
const strayCat = strayCats?.find((catItem) => catItem.assetId === id);
if (strayCat) {
  const isNameSpoofed = catList?.some(
    (c) => c.name.toLowerCase() === strayCat.name.toLowerCase()
  );
  const safeName = isNameSpoofed ? strayCat.assetId : strayCat.name;
  return await addCATToken({ name: safeName, assetId: strayCat.assetId }).unwrap();
}
```

Additionally, display a warning in the UI when a stray cat's name matches a known token name.

---

### Proof of Concept

1. Attacker creates a CAT2 token with metadata name `"USDS"` and a fresh `assetId` (e.g. `deadbeef…`).
2. Attacker sends 1 mojo of this token to the victim's receive address.
3. Victim opens the GUI → Tokens list → sees a stray cat labelled `"USDS"`.
4. Victim toggles the switch to enable it.
5. `handleVisibleChange` → `onShow(assetId)` → `handleShow("deadbeef…")` → `catList.find()` returns `undefined` → `strayCats.find()` returns `{ name: "USDS", assetId: "deadbeef…" }` → `addCATToken({ name: "USDS", assetId: "deadbeef…" })`.
6. A new wallet named `"USDS"` is created, backed by `deadbeef…`.
7. Assert: the new wallet's `assetId` is `deadbeef…`, not the real USDS `assetId` — confirming identity spoofing. [6](#0-5)

### Citations

**File:** packages/wallets/src/hooks/useWalletsList.ts (L63-65)
```typescript
  const { data: strayCats, isLoading: isLoadingGetStrayCats } = useGetStrayCatsQuery(undefined, {
    pollingInterval: 10_000,
  });
```

**File:** packages/wallets/src/hooks/useWalletsList.ts (L189-221)
```typescript
  async function handleShow(id: number | string) {
    try {
      if (typeof id === 'number') {
        show(id);
        return id;
      }

      if (typeof id === 'string') {
        // assign wallet for CAT

        const cat = catList?.find((catItem) => catItem.assetId === id);
        if (cat) {
          return await addCATToken({
            name: cat.name,
            assetId: cat.assetId,
          }).unwrap();
        }

        // assign stray cat
        const strayCat = strayCats?.find((catItem) => catItem.assetId === id);
        if (strayCat) {
          return await addCATToken({
            name: strayCat.name,
            assetId: strayCat.assetId,
          }).unwrap();
        }
      }
      return undefined;
    } catch (error) {
      showError(error);
      return undefined;
    }
  }
```

**File:** packages/api-react/src/services/wallet.ts (L796-805)
```typescript
    getStrayCats: query(build, CAT, 'getStrayCats', {
      transformResponse: (response) =>
        response.strayCats.map(
          (cat: { assetId: string; name: string; firstSeenHeight: number; senderPuzzleHash: string }) => ({
            ...cat,
            assetId: normalizeHex(cat.assetId),
            senderPuzzleHash: normalizeHex(cat.senderPuzzleHash),
          }),
        ),
    }),
```

**File:** packages/api-react/src/services/wallet.ts (L927-948)
```typescript
      async queryFn({ name, ...restArgs }, queryApi, _extraOptions, fetchWithBQ) {
        try {
          const { data, error } = await fetchWithBQ({
            command: 'createWalletForExisting',
            service: CAT,
            args: withAllowUnsynced(queryApi.getState(), restArgs),
          });

          if (error) {
            throw error as Error;
          }

          const walletId = data?.walletId;
          if (!walletId) {
            throw new Error('Wallet id is not defined');
          }

          await fetchWithBQ({
            command: 'setName',
            service: CAT,
            args: { walletId, name },
          });
```
