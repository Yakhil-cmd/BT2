### Title
WalletConnect Dapp Metadata Identity Spoofing in Signing Confirmation Dialog - (File: packages/gui/src/electron/dialogs/Confirm/Confirm.tsx)

### Summary
An unprivileged attacker who controls a WalletConnect dapp can set arbitrary `name`, `description`, and `url` metadata in the WalletConnect session proposal. These fields are accepted with no content validation and are rendered verbatim in the signing/spending confirmation dialog under the "Request from" attribution header. A user who is tricked into pairing with a malicious dapp (e.g., via a phishing QR code) will see the attacker-chosen name and description in every subsequent signing approval prompt, potentially causing them to approve unauthorized transactions believing the request originates from a trusted application.

### Finding Description
In `WalletConnectProvider.tsx`, the `parsePair()` function extracts `metadata.name`, `metadata.url`, `metadata.description`, and `metadata.icons[0]` directly from the WalletConnect `session_proposal` event emitted by the remote dapp:

```js
metadata: {
  name: metadata?.name ?? 'Unknown application',
  url: metadata?.url,
  icon: metadata?.icons?.[0],
  description: metadata?.description,
},
``` [1](#0-0) 

These values are persisted to the pair record via `window.permissionsAPI.registerPair(pair)`. The schema that validates the stored record (`pairMetadataSchema` in `pairSchemas.ts`) applies only `z.string()` — no length limit, no character-class restriction, no format check:

```ts
const pairMetadataSchema = z.object({
  name: z.string(),
  url: z.string().optional(),
  icon: z.string().optional(),
  description: z.string().optional(),
});
``` [2](#0-1) 

The stored metadata is later passed as `pair` into the `Confirm` dialog, which is the per-command signing/spending approval window shown to the user for every WalletConnect RPC call. The dialog renders the attacker-controlled strings directly in the "Request from" attribution block:

```jsx
<span className="... text-chia-text">{pair.metadata.name}</span>
...
<div className="... truncate">{pair.metadata.url}</div>
...
<div className="... truncate">{pair.metadata.description}</div>
``` [3](#0-2) 

The same unvalidated strings are also rendered in the initial pairing dialog (`Pair.tsx`):

```jsx
<h1 ...>{metadata.name || 'Unknown application'}</h1>
{hasUrl && <div ...>{metadata.url}</div>}
``` [4](#0-3) 

### Impact Explanation
Every time the paired dapp sends a `chia_sendTransaction`, `chia_signMessageById`, `chia_takeOffer`, or any other spending/signing command, the `Confirm` dialog is shown with the attacker-chosen name as the authoritative "Request from" label. A user who was socially engineered into pairing with a dapp named `"Chia Official Wallet"` (or any other trusted-sounding string) will see that name on every subsequent approval prompt. Because the name appears in the same visual position as a legitimate application identity, the user has no signal that the string is attacker-controlled. This directly enables approval of unauthorized signing, spending, or offer-acceptance operations — matching the **High** impact category: *spoofing of WalletConnect state that causes a user to approve the wrong identity*.

### Likelihood Explanation
The attacker entry path requires only that the user scan a QR code or paste a `wc:` URI — a standard and widely-used flow. Phishing pages, malicious browser extensions, or compromised dapp front-ends can all deliver such a URI. No leaked keys, host compromise, or cryptographic break is required. The attacker has full control over the WalletConnect session proposal metadata because the WalletConnect protocol places no restrictions on these fields.

### Recommendation
1. **Enforce content constraints on `pairMetadataSchema`**: apply `z.string().max(64)` (or similar) on `name`, `z.string().max(256)` on `description`, and `z.string().url()` (http/https only) on `url`. Reject pairing if validation fails.
2. **Strip or escape non-printable and bidirectional Unicode characters** from `name` and `description` before storage and display.
3. **Add a visual disclaimer** in the `Confirm` dialog making clear that the "Request from" label is self-reported by the dapp and is not verified by Chia.
4. **Validate `url` format** in `parsePair()` before storing, consistent with the existing `isDisplayableUrl` guard already applied at render time in `Confirm.tsx`. [5](#0-4) 

### Proof of Concept
1. Stand up a WalletConnect-compatible dapp server and set the session proposal metadata to:
   ```json
   {
     "name": "Chia Official Wallet",
     "description": "✓ Verified by Chia Network — routine security check",
     "url": "https://chia.net",
     "icons": ["https://chia.net/favicon.ico"]
   }
   ```
2. Generate a `wc:` pairing URI and deliver it to the victim (phishing page, QR code, etc.).
3. Victim scans/pastes the URI; the `Pair.tsx` dialog shows `"Chia Official Wallet"` as the application name. Victim approves.
4. Attacker sends `chia_sendTransaction` targeting the victim's wallet.
5. The `Confirm` dialog renders: **"Request from — Chia Official Wallet"** with the attacker-chosen description below it.
6. Victim, believing the request is from the official Chia wallet, clicks Confirm.
7. The transaction is signed and broadcast; funds are transferred to the attacker's address.

The root cause — `z.string()` with no further constraint in `pairMetadataSchema` and verbatim rendering in `Confirm.tsx` — is directly analogous to the Rocketpool finding where on-chain string fields (timezone, email) were accepted and displayed without format validation, enabling false-information injection in a security-critical UI context.

### Citations

**File:** packages/gui/src/components/walletConnect/WalletConnectProvider.tsx (L208-218)
```typescript
  return {
    topic: pairingTopic,
    mainnet,
    metadata: {
      name: metadata?.name ?? 'Unknown application',
      url: metadata?.url,
      icon: metadata?.icons?.[0],
      description: metadata?.description,
    },
    commands,
  };
```

**File:** packages/gui/src/electron/utils/pairSchemas.ts (L3-8)
```typescript
const pairMetadataSchema = z.object({
  name: z.string(),
  url: z.string().optional(),
  icon: z.string().optional(),
  description: z.string().optional(),
});
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L82-86)
```typescript
function isDisplayableUrl(value: string | undefined): boolean {
  if (!value) return false;
  // Filter out obvious placeholders ('#', '/') and any non-http(s) scheme.
  return /^https?:\/\//i.test(value);
}
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L333-340)
```typescript
                  <span className="text-sm font-semibold truncate text-chia-text">{pair.metadata.name}</span>
                </div>
                {isDisplayableUrl(pair.metadata.url) && (
                  <div className="text-xs text-chia-text-secondary truncate">{pair.metadata.url}</div>
                )}
                {pair.metadata.description && (
                  <div className="mt-1 text-xs text-chia-text-secondary truncate">{pair.metadata.description}</div>
                )}
```

**File:** packages/gui/src/electron/dialogs/Pair/Pair.tsx (L158-162)
```typescript
            <h1 className="m-0 text-2xl font-semibold leading-tight text-chia-text truncate">
              {metadata.name || 'Unknown application'}
            </h1>
            {hasUrl && <div className="mt-0.5 text-sm text-chia-text-secondary truncate">{metadata.url}</div>}
            <p className="mt-0.5 mb-0 text-sm leading-snug text-chia-text-secondary">
```
