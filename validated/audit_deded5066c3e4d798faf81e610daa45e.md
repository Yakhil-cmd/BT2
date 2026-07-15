The regex behavior is real and verifiable. Let me confirm the exact code:

### Title
Greedy Regex in `parseOfferData` Extracts Last Offer String, Enabling Malicious Offer Substitution — (`packages/gui/src/components/offers2/OfferBuilderImport.tsx`, `packages/gui/src/components/offers/OfferImport.tsx`)

---

### Summary

The `parseOfferData` function uses a greedy `.*` capture group for the leading text. When a file contains two bech32 offer strings, the regex engine backtracks to the **last** occurrence of `offer1[...]`, not the first. An attacker who delivers a crafted file containing a legitimate-looking offer string followed by a malicious one causes the victim to review and potentially accept the malicious offer.

---

### Finding Description

Both `OfferBuilderImport.tsx` and `OfferImport.tsx` define an identical `parseOfferData` function:

```typescript
const matches = data.match(
  /(?<leading>.*)(?<offer>offer1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)(?<trailing>.*)/s
);
``` [1](#0-0) [2](#0-1) 

With the `s` (dotAll) flag, `.` matches newlines. The `(?<leading>.*)` group is **greedy**: the engine first consumes the entire input, then backtracks minimally to satisfy `offer1[...]`. This means it finds the **rightmost** (last) occurrence of `offer1[...]`, not the first.

**Deterministic proof:**

```
Input:  "offer1<LEGITIMATE_BLOB>...arbitrary text...offer1<MALICIOUS_BLOB>"
Result: leading = "offer1<LEGITIMATE_BLOB>...arbitrary text..."
        offer   = "offer1<MALICIOUS_BLOB>"
        trailing = ""
```

The extracted `offerData` is then passed directly to `getOfferSummary` and the result is navigated to the offer view: [3](#0-2) 

The same flow exists in `OfferImport.tsx`: [4](#0-3) 

There is no validation that only one offer string is present, no check that the extracted offer matches any expected value, and no warning shown to the user.

---

### Impact Explanation

A victim who drops or opens a crafted file is shown the summary for the **malicious** offer while believing they are reviewing the legitimate one. If they confirm, they execute an attacker-controlled trade — potentially surrendering XCH, CATs, or NFTs for nothing or for a manipulated amount. This is direct asset loss via unsafe handling of an imported file payload.

---

### Likelihood Explanation

The attack surface is the standard offer import workflow (drag-and-drop, file picker, clipboard paste — all three entry points call the same `parseOfferData`). The attacker only needs to deliver a single crafted text file. The regex behavior is deterministic and requires no race condition, timing, or privileged access. The victim has no visual indication that two offer strings were present.

---

### Recommendation

Change `(?<leading>.*)` to a non-greedy `(?<leading>.*?)` so the regex matches the **first** occurrence of `offer1[...]`:

```typescript
/(?<leading>.*?)(?<offer>offer1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)(?<trailing>.*)/s
```

Additionally, consider rejecting input that contains more than one offer string (i.e., if `trailing` itself matches another `offer1[...]` blob, treat the file as invalid and show an error).

The fix must be applied in both files:
- `packages/gui/src/components/offers2/OfferBuilderImport.tsx` line 30
- `packages/gui/src/components/offers/OfferImport.tsx` line 33

---

### Proof of Concept

```typescript
// Unit test — no wallet needed
function parseOfferData(data: string) {
  const matches = data.match(
    /(?<leading>.*)(?<offer>offer1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)(?<trailing>.*)/s
  );
  return matches?.groups?.offer;
}

const legitimate = "offer1qqph8lx0hcc6ze0s3jn54khce6mua7lmqqqxw";
const malicious   = "offer1qpzry9x8gf2tvdw0s3jn54khce6mua7ltest99";
const crafted     = `${legitimate}\n\nSome descriptive text\n\n${malicious}`;

const result = parseOfferData(crafted);
console.assert(result === legitimate, "FAIL: got malicious offer");
// This assertion FAILS — result === malicious
```

Running this test confirms the greedy regex returns the second (malicious) blob, not the first.

### Citations

**File:** packages/gui/src/components/offers2/OfferBuilderImport.tsx (L30-31)
```typescript
    const matches = data.match(/(?<leading>.*)(?<offer>offer1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)(?<trailing>.*)/s);
    return [matches?.groups?.offer, matches?.groups?.leading, matches?.groups?.trailing];
```

**File:** packages/gui/src/components/offers2/OfferBuilderImport.tsx (L34-48)
```typescript
  async function parseOfferSummary(rawOfferData: string) {
    const [offerData] = parseOfferData(rawOfferData);
    if (!offerData) {
      throw new Error(t`Could not parse offer data`);
    }

    const { summary } = await getOfferSummary({ offerData }).unwrap();

    if (summary) {
      navigate('/dashboard/offers/view', {
        state: {
          offerData,
          offerSummary: summary,
          imported: true,
          referrerPath: '/dashboard/offers',
```

**File:** packages/gui/src/components/offers/OfferImport.tsx (L33-34)
```typescript
    const matches = data.match(/(?<leading>.*)(?<offer>offer1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)(?<trailing>.*)/s);
    return [matches?.groups?.offer, matches?.groups?.leading, matches?.groups?.trailing];
```

**File:** packages/gui/src/components/offers/OfferImport.tsx (L37-64)
```typescript
  async function parseOfferSummary(rawOfferData: string, offerFilePath: string | undefined) {
    const [offerData /* , leadingText, trailingText */] = parseOfferData(rawOfferData);
    let offerSummary: OfferSummaryRecord | DataLayerOfferSummary | undefined;

    if (offerData) {
      const { data: response } = await getOfferSummary({ offerData });
      const { summary, success } = response;

      if (success) {
        offerSummary = summary;
      }
    } else {
      console.warn('Unable to parse offer data');
    }

    if (offerSummary) {
      let navigationPath: string;
      if (isDataLayerOfferSummary(offerSummary)) {
        navigationPath = '/dashboard/offers/view';
      } else {
        navigationPath = offerContainsAssetOfType(offerSummary, 'singleton')
          ? '/dashboard/offers/view-nft'
          : '/dashboard/offers/view';
      }

      navigate(navigationPath, {
        state: { offerData, offerSummary, offerFilePath, imported: true },
      });
```
