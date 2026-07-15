The bug is confirmed. Here is the analysis:

**Root cause confirmed:**

`KeyringStatus` defines `passphraseRequirements` with the field `min_length` (snake_case): [1](#0-0) 

But `validateChangePassphraseParams` destructures `minLength` (camelCase), aliasing it to `minPassphraseLength`: [2](#0-1) 

Since `minLength` does not exist on the object, `minPassphraseLength` is always `undefined`. The guard condition `newPassphrase.length < undefined` evaluates to `false` in JavaScript (any numeric comparison with `undefined` yields `false`), so the length check is permanently dead: [3](#0-2) 

**Impact assessment:**

The bug is real and the code path is reachable via the "Set Passphrase" and "Change Passphrase" UI flows in `SetPassphrasePrompt` and `ChangePassphrasePrompt`, both of which call `validateChangePassphraseParams` as the sole client-side gate before calling `setKeyringPassphrase`: [4](#0-3) 

**However**, the critical question for bounty eligibility is whether the daemon enforces `min_length` server-side when `set_keyring_passphrase` is called. The GUI validation is purely client-side. If the daemon independently enforces the minimum length, the RPC call would fail and the weak passphrase would not be accepted. The GUI bug would then be a UX/error-message issue (the daemon rejects it with a less friendly error), not a security bypass.

**Verdict:**

The bug is a confirmed client-side validation bypass due to a `min_length` vs `minLength` naming mismatch. The minimum passphrase length check is completely non-functional in the GUI. Whether this constitutes a bounty-grade High finding depends on daemon-side enforcement, which is outside this repo's scope. Within the GUI code alone, the invariant is violated: any non-empty passphrase (including `'a'`) passes `validateChangePassphraseParams` regardless of the configured `min_length`.

Per the scope rules, this is a **bypass of passphrase restrictions** — the configured minimum length policy is silently ignored, allowing a user to set a trivially weak passphrase that weakens keyring protection. If the daemon does not re-enforce the minimum, this is a **valid High finding**.

---

### Title
Passphrase Minimum Length Bypass via `min_length`/`minLength` Naming Mismatch — (`packages/core/src/hooks/useValidateChangePassphraseParams.tsx`)

### Summary
`validateChangePassphraseParams` destructures `minLength` (camelCase) from `passphraseRequirements`, but the `KeyringStatus` type defines the field as `min_length` (snake_case). This causes `minPassphraseLength` to always be `undefined`, making the length guard `newPassphrase.length < undefined` permanently `false`. Any non-empty passphrase, including a single character, passes client-side validation regardless of the daemon-configured minimum.

### Finding Description
In `packages/core/src/hooks/useValidateChangePassphraseParams.tsx` line 26:
```ts
const { isOptional: allowEmptyPassphrase, minLength: minPassphraseLength } = keyringState.passphraseRequirements;
```
The actual field name from the daemon is `min_length` (as typed in `packages/api/src/@types/KeyringStatus.ts` line 7). TypeScript does not catch this because the destructuring of a non-existent property is valid JS/TS and simply yields `undefined`. The condition on line 32 (`newPassphrase.length < minPassphraseLength`) is therefore `n < undefined` which is always `false`.

### Impact Explanation
A user can set a 1-character passphrase on their keyring even when the daemon reports `min_length: 8` (or any value > 1). If the daemon does not independently enforce the minimum on the `set_keyring_passphrase` RPC, the keyring is protected by a trivially brute-forceable passphrase, undermining the entire passphrase protection mechanism for wallet keys.

### Likelihood Explanation
The bug is triggered by any user who sets or changes their passphrase to a value shorter than the configured minimum. No special privileges or attacker interaction are required — it is a self-service UI flow available to any local user of the application.

### Recommendation
Fix the destructuring to use the correct snake_case field name:
```ts
const { isOptional: allowEmptyPassphrase, min_length: minPassphraseLength } = keyringState.passphraseRequirements;
```
Alternatively, update the `KeyringStatus` type to use camelCase (`minLength`) and ensure the API response is transformed accordingly.

### Proof of Concept
Unit-test `validateChangePassphraseParams` with a mocked `keyringState` where `passphraseRequirements = { isOptional: false, min_length: 8 }` and call with `newPassphrase='a'`, `confirmationPassphrase='a'`. The function returns `true` (validation passes) instead of the expected `false`, confirming the bypass.

### Citations

**File:** packages/api/src/@types/KeyringStatus.ts (L7-7)
```typescript
  passphraseRequirements: { isOptional: boolean; min_length: number };
```

**File:** packages/core/src/hooks/useValidateChangePassphraseParams.tsx (L26-26)
```typescript
      const { isOptional: allowEmptyPassphrase, minLength: minPassphraseLength } = keyringState.passphraseRequirements;
```

**File:** packages/core/src/hooks/useValidateChangePassphraseParams.tsx (L30-33)
```typescript
      } else if (
        (newPassphrase.length === 0 && !allowEmptyPassphrase) || // Passphrase required, no passphrase provided
        (newPassphrase.length > 0 && newPassphrase.length < minPassphraseLength)
      ) {
```

**File:** packages/gui/src/components/settings/SetPassphrasePrompt.tsx (L67-78)
```typescript
  async function validateDialog(passphrase: string, confirmation: string): Promise<boolean> {
    let isValid = false;

    if (passphrase === '' && confirmation === '') {
      await openDialog(
        <AlertDialog>
          <Trans>Please enter a passphrase</Trans>
        </AlertDialog>,
      );
    } else {
      isValid = await validateChangePassphraseParams(null, passphrase, confirmation);
    }
```
