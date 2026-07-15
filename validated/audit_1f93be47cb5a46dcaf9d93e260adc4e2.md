Looking at the full code path carefully before rendering a verdict.

**Tracing the attack:**

1. **Attacker entry point**: An unprivileged attacker sends a CAT token to the victim's wallet address with a memo/name set to `"USDS"`. The Chia wallet daemon's `get_stray_cats` RPC returns this token with the attacker-controlled `name` field. [1](#0-0) 

2. **Search filter — no type guard**: The `useMemo` list in `useWalletsList` builds a flat array of all token types (`WALLET`, `CAT_LIST`, `STRAY_CAT`) and then applies a single name-based filter with no type exclusion: [2](#0-1) 

   A stray cat named `"USDS"` passes this filter identically to the legitimate USDS `CAT_LIST` entry.

3. **No visual distinction in the UI**: `WalletTokenCard` renders both `CAT_LIST` and `STRAY_CAT` items identically — an editable name field, the assetId as a subtitle, and a toggle switch. There is no "Unknown", "Unverified", or "Stray" label rendered for `STRAY_CAT` items: [3](#0-2) 

4. **Ordering provides weak separation, not protection**: `getTypeOrder` sorts `STRAY_CAT` after `CAT_LIST`, so the fake token appears below the real one — but both are present in the same unstyled list with no categorical header or warning badge. [4](#0-3) 

5. **Import path — no confirmation**: When the user toggles the stray cat on, `handleShow` calls `addCATToken` directly with the attacker-controlled `name` and `assetId`, with no confirmation dialog or warning that this is an unverified token: [5](#0-4) 

---

### Title
Stray CAT name spoofing surfaces attacker-controlled tokens in legitimate token search results without visual distinction — (`packages/wallets/src/hooks/useWalletsList.ts`)

### Summary
An unprivileged attacker who sends a CAT token to a victim's address with a name matching a legitimate token (e.g., `"USDS"`) causes that fake token to appear in the "Manage token list" search results alongside the real token, with no UI differentiation, leading the user to import the wrong asset.

### Finding Description
`useWalletsList` aggregates `WALLET`, `CAT_LIST`, and `STRAY_CAT` entries into a single flat list and applies a case-insensitive substring filter on `token.name` with no type-based exclusion. Stray cat names originate from the `get_stray_cats` RPC, which reflects attacker-supplied memo data from blockchain transactions. `WalletTokenCard` renders all non-`WALLET` entries identically — there is no badge, label, color, or section header distinguishing a `STRAY_CAT` from a `CAT_LIST` entry. The only differentiator is the assetId subtitle, which most users will not recognize as wrong.

### Impact Explanation
The user imports the attacker's token believing it is the legitimate USDS. Their wallet now displays a fake USDS balance. This directly enables downstream harm: the user may accept an offer trading real XCH or CATs for the fake USDS, or may send the fake token to a counterparty. This satisfies the High impact criterion: *"causes a user to… import… the wrong asset."*

### Likelihood Explanation
The attacker only needs the victim's wallet receive address (publicly derivable from any prior transaction) and the ability to send a dust CAT transaction with a spoofed name memo — both are trivially achievable on-chain with no special privileges.

### Recommendation
- Render a visible "Unverified" or "Unknown token" badge on all `STRAY_CAT` entries in `WalletTokenCard`.
- Add a section separator or warning header in `WalletsManageTokens` between `CAT_LIST` and `STRAY_CAT` groups.
- Optionally, exclude `STRAY_CAT` entries from search results entirely unless the user explicitly opts in to viewing unverified tokens.

### Proof of Concept
Unit-test `useWalletsList` with:
- `catList = [{ assetId: 'real-asset-id', name: 'USDS', symbol: 'USDS' }]`
- `strayCats = [{ assetId: 'fake-asset-id', name: 'USDS', firstSeenHeight: 1, senderPuzzleHash: '0xabc' }]`
- `search = 'USDS'`

Assert that the returned list contains two entries, both with `name === 'USDS'`, and that the `STRAY_CAT` entry has no UI-level property distinguishing it from the `CAT_LIST` entry. Then toggle the `STRAY_CAT` entry on and assert `addCATToken` is called with `assetId: 'fake-asset-id'` — confirming the wrong asset is imported.

### Citations

**File:** packages/api/src/@types/CATToken.ts (L9-14)
```typescript
export type CATTokenStray = {
  assetId: string;
  name: string;
  firstSeenHeight: number;
  senderPuzzleHash: string;
};
```

**File:** packages/wallets/src/hooks/useWalletsList.ts (L34-45)
```typescript
function getTypeOrder(item: ListItem) {
  switch (item.type) {
    case 'WALLET':
      return 0;
    case 'CAT_LIST':
      return 1;
    case 'STRAY_CAT':
      return 2;
    default:
      return 3;
  }
}
```

**File:** packages/wallets/src/hooks/useWalletsList.ts (L182-184)
```typescript
    if (search) {
      tokens = tokens.filter((token) => token.name.toLowerCase().includes(search.toLowerCase()));
    }
```

**File:** packages/wallets/src/hooks/useWalletsList.ts (L207-214)
```typescript
        // assign stray cat
        const strayCat = strayCats?.find((catItem) => catItem.assetId === id);
        if (strayCat) {
          return await addCATToken({
            name: strayCat.name,
            assetId: strayCat.assetId,
          }).unwrap();
        }
```

**File:** packages/wallets/src/components/WalletTokenCard.tsx (L147-198)
```typescript
  return (
    <CardListItem>
      <Flex gap={1} alignItems="center" width="100%">
        <Flex flexDirection="column" gap={0.5} flexGrow={1} flexBasis={0} minWidth={0}>
          {walletType === WalletType.STANDARD_WALLET ? (
            <Typography noWrap>{name}</Typography>
          ) : (
            <Form methods={form} onSubmit={handleSubmit}>
              <TextField
                name="name"
                label="Name"
                onBlur={(event) => handleRename(event.target.value)}
                disabled={isLoading}
                size="small"
                fullWidth
                hiddenLabel
              />
            </Form>
          )}
          {(!!subTitle || assetId) && (
            <Flex flexDirection="column" flexGrow={1} flexBasis={0} minWidth={0}>
              {!!subTitle && (
                <Tooltip title={subTitle} placement="right" copyToClipboard>
                  <Typography color="textSecondary" variant="caption" noWrap>
                    {subTitle}
                  </Typography>
                </Tooltip>
              )}
              {assetId && (
                <Link href={`https://www.taildatabase.com/tail/${assetId}`} target="_blank" variant="caption">
                  <Trans>Search on Tail Database</Trans>
                </Link>
              )}
            </Flex>
          )}
        </Flex>
        {walletType !== WalletType.STANDARD_WALLET && (
          <Box width="60px" textAlign="center" position="relative">
            <Box position="absolute" top="0" left="25%">
              <CircularProgress size={34} sx={{ zIndex: -1, opacity: isLoading ? 1 : 0 }} />
            </Box>
            <Switch
              checked={!hidden}
              onChange={handleVisibleChange}
              disabled={isChangingVisibility}
              sx={{ opacity: isLoading ? 0 : 1 }}
            />
          </Box>
        )}
      </Flex>
    </CardListItem>
  );
```
