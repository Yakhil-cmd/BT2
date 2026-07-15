### Title
Unauthorized Signing of Arbitrary Messages via Wallet Address, NFT, or DID Without Re-Authentication — (File: `packages/gui/src/components/signVerify/SignMessage.tsx`)

### Summary
Once the Chia GUI wallet is unlocked, any actor with access to the active session can navigate to **Settings → Advanced → Create Signature** and produce valid cryptographic signatures over arbitrary messages using the wallet's address, NFT identity, or DID identity — with no passphrase re-prompt or any other authentication gate. The signing flow in `SignMessage.tsx` calls `sign_message_by_address` / `sign_message_by_id` directly upon form submission.

### Finding Description
`SettingsAdvanced.tsx` opens the sign dialog with a single call and no credential check:

```tsx
function handleCreateSignature() {
  openDialog(<SignVerifyDialog mode={SignVerifyDialogMode.Sign} />);
}
``` [1](#0-0) 

`SignVerifyDialog` renders `SignMessage` directly: [2](#0-1) 

Inside `SignMessage`, `handleSign()` dispatches `signMessageByAddress` or `signMessageById` immediately on form submit — no passphrase prompt, no keyring re-lock check, no confirmation dialog:

```tsx
async function handleSignByAddress(messageToSign: string, address: string) {
  const result = await signMessageByAddress({ message: messageToSign, address }).unwrap();
  openDialog(<SignMessageResultDialog content={jsonContent} />);
}
``` [3](#0-2) 

```tsx
async function handleSignById(messageToSign: string, id: string, address: string) {
  const { data: result, error } = await signMessageById({ message: messageToSign, id });
  openDialog(<SignMessageResultDialog content={jsonContent} />);
}
``` [4](#0-3) 

The submit handler calls `handleSign()` with no interstitial guard: [5](#0-4) 

**Contrast with the WalletConnect path:** `chia_signMessageByAddress` and `chia_signMessageById` are defined in `Commands.ts` **without** `allowConfirmationBypass`, meaning every WalletConnect-initiated signing request always shows a confirmation dialog to the user. [6](#0-5) 

The `dispatchPairRequest` enforces this: if a command is not in the bypass list, `confirm()` is called before execution. [7](#0-6) 

The local GUI path has **no equivalent guard**.

### Impact Explanation
An actor who gains access to an unlocked Chia GUI session (physical access to an unattended machine, or low-privileged malware capable of GUI interaction) can:

1. Open Settings → Advanced → Create Signature.
2. Select any wallet address, NFT, or DID belonging to the logged-in key.
3. Type an arbitrary message and click **Sign**.
4. Receive a valid BLS signature that cryptographically proves ownership of that address, NFT identity, or DID.

This constitutes **unauthorized signing affecting NFT and DID** (Critical scope) and a **bypass of signing approval with direct security impact** (High scope). The resulting signature is indistinguishable from one the legitimate owner produced intentionally and can be used for identity impersonation, proof-of-ownership claims, or signing attacker-controlled content under the victim's identity.

### Likelihood Explanation
The wallet remains unlocked for the entire session after the initial passphrase entry (or indefinitely if no passphrase is set). The sign dialog is reachable in two clicks from the main settings panel. No elevated OS privilege is required — any process that can simulate GUI input or any person who walks up to an unattended machine can exploit this.

### Recommendation
- Before executing any signing operation in `SignMessage.tsx`, prompt the user to re-enter their keyring passphrase (mirroring the pattern used in `RemovePassphrasePrompt` / `ChangePassphrasePrompt`).
- If no passphrase is set, display a warning that signing is proceeding without re-authentication and recommend setting one.
- Consider a session-level signing timeout so that re-authentication is required after a period of inactivity.

### Proof of Concept
1. Launch Chia GUI and log in (with or without a passphrase — once unlocked, the session stays open).
2. Navigate to **Settings → Advanced**.
3. Click **Create Signature**.
4. In the dialog, select **Wallet Address** (or NFT / DID), enter any message (e.g., `"attacker controlled payload"`), and click **Sign**.
5. Observe that a valid JSON signature blob is returned immediately — no passphrase prompt, no confirmation dialog, no re-authentication of any kind. [8](#0-7) [9](#0-8)

### Citations

**File:** packages/gui/src/components/settings/SettingsAdvanced.tsx (L51-57)
```typescript
  function handleCreateSignature() {
    openDialog(<SignVerifyDialog mode={SignVerifyDialogMode.Sign} />);
  }

  function handleVerifySignature() {
    openDialog(<SignVerifyDialog mode={SignVerifyDialogMode.Verify} />);
  }
```

**File:** packages/gui/src/components/signVerify/SignVerifyDialog.tsx (L38-41)
```typescript
  const content = {
    [SignVerifyDialogMode.Sign]: <SignMessage onComplete={handleCompletion} />,
    [SignVerifyDialogMode.Verify]: <VerifyMessage onComplete={handleCompletion} />,
  }[mode];
```

**File:** packages/gui/src/components/signVerify/SignMessage.tsx (L59-85)
```typescript
  async function handleSignByAddress(messageToSign: string, address: string) {
    if (!messageToSign) {
      showError(new Error(t`Enter a message to sign`));
      return;
    }

    if (!address) {
      showError(new Error(t`Enter a wallet address to sign with`));
      return;
    }

    try {
      const result = await signMessageByAddress({
        message: messageToSign,
        address,
      }).unwrap();

      const content = toSnakeCase({ ...result, message: messageToSign, address });
      delete content.success;

      const jsonContent = JSON.stringify(content, null, 2);

      openDialog(<SignMessageResultDialog content={jsonContent} />);
    } catch (error) {
      showError(error);
    }
  }
```

**File:** packages/gui/src/components/signVerify/SignMessage.tsx (L87-127)
```typescript
  async function handleSignById(messageToSign: string, id: string, address: string) {
    if (!messageToSign) {
      showError(new Error(t`Enter a message to sign`));
      return;
    }

    if (!id) {
      showError(new Error(t`Enter an NFT or DID to sign with`));
      return;
    }

    const { data: result, error } = await signMessageById({
      message: messageToSign,
      id,
    });

    if (error) {
      const missingNFTMatch = error.message.match(/^NFT for (.*) doesn't exist/);
      const missingDIDMatch = error.message.match(/^DID for (.*) doesn't exist/);

      if (missingNFTMatch || missingDIDMatch) {
        const entityPuzzleHash = missingNFTMatch ? missingNFTMatch[1] : missingDIDMatch![1];
        const entityId = toBech32m(entityPuzzleHash, missingNFTMatch ? 'nft' : 'did:chia:');

        if (missingNFTMatch) {
          showError(new Error(t`Unable to find NFT ${entityId}`));
        } else {
          showError(new Error(t`Unable to find DID ${entityId}`));
        }
      } else {
        showError(error);
      }
    } else {
      const content = toSnakeCase({ ...result, message: messageToSign, address });
      delete content.success;

      const jsonContent = JSON.stringify(content, null, 2);

      openDialog(<SignMessageResultDialog content={jsonContent} />);
    }
  }
```

**File:** packages/gui/src/components/signVerify/SignMessage.tsx (L129-153)
```typescript
  async function handleSign() {
    if (!entity) {
      showError(new Error(ERROR_MISSING_ENTITY));
      return;
    }

    switch (selectedEntityType) {
      case SignMessageEntityType.WalletAddress:
        await handleSignByAddress(message, (entity as SignMessageWalletAddressEntity).address);
        break;
      case SignMessageEntityType.NFT:
        await handleSignById(message, (entity as SignMessageNFTEntity).nftId, (entity as SignMessageNFTEntity).address);
        break;
      case SignMessageEntityType.DID:
        await handleSignById(message, (entity as SignMessageDIDEntity).didId, (entity as SignMessageDIDEntity).address);
        break;
      default:
        throw new Error(`Unknown entity type used for signing: ${selectedEntityType}`);
    }
  }

  async function handleSubmit() {
    onComplete();
    await handleSign();
  }
```

**File:** packages/gui/src/electron/commands/Commands.ts (L372-420)
```typescript
  'chia_wallet.sign_message_by_address': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Sign Message' }),
    message: () => i18n._(/* i18n */ { id: 'Are you sure you want to sign this message?' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Sign' }),
    params: [
      { name: 'address', label: () => i18n._(/* i18n */ { id: 'Address' }), type: 'string' },
      { name: 'message', label: () => i18n._(/* i18n */ { id: 'Message' }), type: 'string' },
      {
        name: 'is_hex',
        label: () => i18n._(/* i18n */ { id: 'Message Is Hex Encoded String' }),
        type: 'bool',
        isOptional: true,
      },
      {
        name: 'safe_mode',
        label: () => i18n._(/* i18n */ { id: 'Safe Mode' }),
        type: 'bool',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_signMessageByAddress',
        title: () => i18n._(/* i18n */ { id: 'Sign Message by Address' }),
      },
    ],
  },

  'chia_wallet.sign_message_by_id': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Sign Message' }),
    message: () => i18n._(/* i18n */ { id: 'Are you sure you want to sign this message?' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Sign' }),
    params: [
      { name: 'id', label: () => i18n._(/* i18n */ { id: 'Id' }), type: 'string' },
      { name: 'message', label: () => i18n._(/* i18n */ { id: 'Message' }), type: 'string' },
      {
        name: 'is_hex',
        label: () => i18n._(/* i18n */ { id: 'Message Is Hex Encoded String' }),
        type: 'bool',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_signMessageById',
        title: () => i18n._(/* i18n */ { id: 'Sign Message by Id' }),
      },
    ],
  },
```

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L56-66)
```typescript
  // if command is bypassed return true
  if (pair.bypass.includes(command)) {
    return process(context);
  }

  const isAllowed = await confirm();
  if (isAllowed === true) {
    return process(context);
  }

  throw new WcError(`Command not allowed for this pair.`, WcErrorCode.UNAUTHORIZED_METHOD);
```
