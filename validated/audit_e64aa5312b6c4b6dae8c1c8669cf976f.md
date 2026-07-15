### Title
NFT Offer Validity Always Returns False, Permanently Disabling Accept Offer Button - (File: `packages/gui/src/components/offers/NFTOfferViewer.tsx`)

### Summary
In `NFTOfferViewer.tsx`, the `checkOfferValidity` response is accessed via `response.data?.valid` instead of `response.valid`. Because the mutation's `transformResponse` spreads fields to the top level (no `.data` wrapper), `response.data` is always `undefined`, making `valid` always `false`. This permanently disables the "Accept Offer" button and displays a false "invalid" banner for every imported NFT offer, regardless of actual on-chain validity.

### Finding Description

The `checkOfferValidity` RTK Query mutation is defined in `packages/api-react/src/services/wallet.ts` with a `transformResponse` that spreads the daemon response directly to the top level:

```js
checkOfferValidity: mutation(build, WalletService, 'checkOfferValidity', {
  transformResponse: (response) => ({
    ...response,
    id: normalizeHex(response.id),
  }),
}),
``` [1](#0-0) 

After `.unwrap()`, the resolved value has shape `{ valid: boolean, id: string, success: boolean }` — there is no `.data` sub-object. The `WalletService` type confirms this:

```ts
async checkOfferValidity(args: { offer: string }) {
  return this.command<{ id: string; valid: boolean }>('check_offer_validity', args);
}
``` [2](#0-1) 

In `NFTOfferDetails` inside `NFTOfferViewer.tsx`, the validity check reads:

```js
const response = await checkOfferValidity({ offer: offerData }).unwrap();
valid = response.data?.valid === true;   // ← BUG: response.data is always undefined
``` [3](#0-2) 

`response.data` is always `undefined`, so `undefined === true` is always `false`, and `setIsValid(false)` is always called in the `finally` block. [4](#0-3) 

The correct pattern — used in the sibling component `OfferBuilderViewer.tsx` — is `response.valid`:

```js
const response = await checkOfferValidity({ offer: offerData }).unwrap();
setIsValid(response.valid === true);   // ← correct
``` [5](#0-4) 

### Impact Explanation

With `isValid` permanently `false` for any imported NFT offer, three UI elements are broken simultaneously:

1. **Accept Offer button is permanently disabled** — `disabled={!isValid || isMissingRequestedAsset || isLoading}` evaluates to `disabled={true}` for every imported NFT offer, making it impossible to accept any valid NFT offer through this viewer. [6](#0-5) 

2. **Fee input is permanently hidden** — `{imported && isValid && (` is never true, so the network fee field is never rendered. [7](#0-6) 

3. **False "invalid" banner is always shown** — `isInvalid={!isCheckOfferValidityLoading && !isValid}` is always `true`, causing `OfferHeader` to display: *"This offer is no longer valid because it was accepted or cancelled."* [8](#0-7) [9](#0-8) 

This matches the allowed High impact: *"Corruption, spoofing, or unsafe trust of… offer… state that causes a user to… display the wrong… status"* — and goes further by completely blocking offer acceptance.

### Likelihood Explanation

This is triggered by any user who opens an imported NFT offer (i.e., `imported=true` and `offerData` is provided). No special attacker capability is required; the bug fires unconditionally on every execution of the validity-check path in `NFTOfferDetails`. Any counterparty who sends a valid NFT offer to a victim user will find the victim's GUI permanently blocks acceptance and falsely labels the offer as cancelled/invalid.

### Recommendation

Change line 414 of `packages/gui/src/components/offers/NFTOfferViewer.tsx` from:

```js
valid = response.data?.valid === true;
```

to:

```js
valid = response.valid === true;
```

This matches the correct access pattern already used in `OfferBuilderViewer.tsx`. [5](#0-4) 

### Proof of Concept

1. Receive a valid NFT offer file from a counterparty.
2. In the Chia GUI, navigate to **Offers → Import Offer** and load the offer file, which renders `NFTOfferViewer` with `imported=true` and `offerData` set.
3. `NFTOfferDetails` fires the `useMemo` async block, calls `checkOfferValidity({ offer: offerData }).unwrap()`, and reads `response.data?.valid` — which is `undefined` because the response has no `.data` wrapper.
4. `valid` remains `false`; `setIsValid(false)` is called.
5. Observe: the `OfferHeader` displays *"This offer is no longer valid because it was accepted or cancelled"* in red, the fee input is absent, and the **Accept Offer** button is greyed out and unclickable (`disabled={true}`).
6. The offer cannot be accepted through the GUI regardless of its actual on-chain validity.

### Citations

**File:** packages/api-react/src/services/wallet.ts (L720-725)
```typescript
    checkOfferValidity: mutation(build, WalletService, 'checkOfferValidity', {
      transformResponse: (response) => ({
        ...response,
        id: normalizeHex(response.id),
      }),
    }),
```

**File:** packages/api/src/services/WalletService.ts (L363-365)
```typescript
  async checkOfferValidity(args: { offer: string }) {
    return this.command<{ id: string; valid: boolean }>('check_offer_validity', args);
  }
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L412-414)
```typescript
      const response = await checkOfferValidity({ offer: offerData }).unwrap();

      valid = response.data?.valid === true;
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L417-419)
```typescript
    } finally {
      setIsValid(valid);
    }
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L446-447)
```typescript
          isInvalid={!isCheckOfferValidityLoading && !isValid}
          isComplete={tradeRecord?.status === OfferState.CONFIRMED}
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L602-603)
```typescript
              {imported && isValid && (
                <Flex flexDirection="column" gap={2}>
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L635-643)
```typescript
                    <ButtonLoading
                      variant="contained"
                      color="primary"
                      type="submit"
                      disabled={!isValid || isMissingRequestedAsset || isLoading}
                      loading={isAccepting}
                    >
                      <Trans>Accept Offer</Trans>
                    </ButtonLoading>
```

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L136-137)
```typescript
      const response = await checkOfferValidity({ offer: offerData }).unwrap();
      setIsValid(response.valid === true);
```

**File:** packages/gui/src/components/offers/OfferHeader.tsx (L43-57)
```typescript
  if (!headerElement && isInvalid) {
    headerElement = (
      <Typography variant="subtitle1" color="error">
        <Trans>
          {'This offer is no longer valid because it was accepted or cancelled. Click '}
          <Link
            target="_blank"
            href="https://docs.chia.net/getting-started/wallet-guide/#taker-attempts-to-accept-an-invalid-offer"
          >
            here
          </Link>{' '}
          to learn more.
        </Trans>
      </Typography>
    );
```
