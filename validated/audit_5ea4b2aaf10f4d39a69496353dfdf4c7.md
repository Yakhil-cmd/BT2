### Title
WebAuthn Transaction Signature Accepted Without Origin Validation, Enabling Cross-Origin Phishing-Based Transaction Authorization Bypass - (File: `model/flow/webauthn.go`)

### Summary

The Flow FVM's WebAuthn authentication scheme (`WebAuthnScheme`) parses the `origin` field from `clientDataJSON` but never validates it against any expected value. The W3C WebAuthn specification requires origin validation as the primary phishing-resistance guarantee. Without it, an attacker can trick a victim holding a WebAuthn-keyed Flow account into signing a crafted transaction challenge on a malicious website, then submit the resulting assertion — bearing any arbitrary origin — as a valid Flow transaction signature. The FVM accepts it unconditionally.

### Finding Description

`validateWebAuthNExtensionData` in `model/flow/webauthn.go` performs the following checks on a WebAuthn assertion embedded in a `TransactionSignature.ExtensionData`:

1. `clientData.Type == "webauthn.get"` — checked ✓
2. Challenge == `SHA2_256(TransactionDomainTag || payload)` — checked ✓
3. `rpIdHash != TransactionDomainTag` — checked (trivially weak) ✓
4. Authenticator flags (UP, BE/BS, AT/ED) — checked ✓
5. **`clientData.Origin` — never checked ✗** [1](#0-0) 

After parsing `clientData` (which includes the `Origin` field), the code only validates `Type` and the challenge length/value. The `Origin` field is silently ignored: [2](#0-1) 

This is confirmed by the test suite, which explicitly marks an **empty origin as valid**: [3](#0-2) 

The full verification path is:

`transactionExecutor.preprocess()` → `TransactionVerifier.CheckAuthorization()` → `verifyTransaction()` → `signatureContinuation.verify()` → `ValidateExtensionDataAndReconstructMessage()` → `validateWebAuthNExtensionData()` [4](#0-3) [5](#0-4) 

### Impact Explanation

An attacker who wants to execute transaction `T` on behalf of a victim with a WebAuthn-keyed Flow account proceeds as follows:

1. Attacker constructs the target transaction `T` (e.g., transferring tokens from victim's account).
2. Attacker computes the WebAuthn challenge: `SHA2_256(TransactionDomainTag || T.EnvelopeMessage())`.
3. Attacker deploys a phishing page at `https://evil.com` that initiates a WebAuthn `get` ceremony with this exact challenge.
4. Victim visits the phishing page and performs a WebAuthn gesture (e.g., Touch ID, Face ID, security key).
5. The browser produces an assertion with `origin = "https://evil.com"` and `rpIdHash = SHA256("evil.com")`.
6. Attacker wraps this assertion into a `TransactionSignature.ExtensionData` with `WebAuthnScheme` byte prefix and submits `T` to the network.
7. The FVM calls `validateWebAuthNExtensionData`, which validates the challenge (matches `T`), validates the flags, and ignores the origin entirely — returning `(true, message)`.
8. The cryptographic signature over `authenticatorData || SHA256(clientDataJSON)` verifies against the victim's registered public key.
9. Transaction `T` executes with the victim's authorization.

The impact is **unauthorized transaction execution** — any transaction requiring the victim's WebAuthn key signature can be executed without the victim's knowledge of what they are authorizing. This includes asset transfers, contract deployments, and any other privileged Cadence operations. [6](#0-5) 

The `rpIdHash` check at line 125 only excludes the value `TransactionDomainTag` itself — any other 32-byte value (including `SHA256("evil.com")`) passes. This provides no meaningful binding to a legitimate relying party.

### Likelihood Explanation

**Likelihood: 2.** The attacker requires no privileged access. Preconditions are:
- Victim holds a Flow account with a WebAuthn-scheme key (increasingly common as FLIP 264 rolls out).
- Attacker knows the victim's account address and key index (public on-chain information).
- Attacker can serve a phishing page and trick the victim into a single WebAuthn gesture.

WebAuthn is specifically marketed as phishing-resistant; users are conditioned to trust WebAuthn prompts. The absence of origin validation completely removes this protection without any visible indicator to the victim.

### Recommendation

In `validateWebAuthNExtensionData`, enforce that `clientData.Origin` is non-empty and matches a set of expected Flow wallet origins (or at minimum is non-empty). Additionally, validate that `rpIdHash` equals `SHA256(expectedRpId)` derived from the allowed origin, consistent with W3C WebAuthn §7.2 steps 11–13. If Flow intentionally omits origin binding (e.g., for native app authenticators), this design decision must be explicitly documented and the security trade-off acknowledged, as it eliminates phishing resistance entirely. [7](#0-6) 

### Proof of Concept

```
// Attacker-controlled inputs:
targetTx := buildMaliciousTransaction(victimAddress, victimKeyIndex)
envelopeMsg := targetTx.EnvelopeMessage()

// Challenge the FVM will accept:
challenge := SHA2_256(TransactionDomainTag || envelopeMsg)
challengeB64 := base64url.Encode(challenge)

// Phishing page presents WebAuthn get() with options.challenge = challengeB64
// Victim authenticates → browser returns assertion:
//   clientDataJSON = {"type":"webauthn.get","challenge":"<challengeB64>","origin":"https://evil.com"}
//   authenticatorData = rpIdHash(evil.com) || flags(UP=1) || sigCounter
//   signature = ECDSA(authenticatorData || SHA256(clientDataJSON), victimPrivKey)

// Attacker constructs extension data:
webAuthnData := WebAuthnExtensionData{AuthenticatorData: authenticatorData, ClientDataJson: clientDataJSON}
extData := [0x01] + RLP(webAuthnData)  // WebAuthnScheme prefix

// Submit transaction:
targetTx.EnvelopeSignatures = [{Address: victimAddress, KeyIndex: victimKeyIndex,
                                  Signature: signature, ExtensionData: extData}]
// FVM validateWebAuthNExtensionData:
//   ✓ type == "webauthn.get"
//   ✓ challenge == SHA2_256(TransactionDomainTag || envelopeMsg)
//   ✓ rpIdHash != TransactionDomainTag  (SHA256("evil.com") != TransactionDomainTag)
//   ✓ flags: UP set, no extension data mismatch
//   ✗ origin: never checked
// → returns (true, authenticatorData || SHA256(clientDataJSON))
// Cryptographic verify passes → transaction executes as victim
```

### Citations

**File:** model/flow/webauthn.go (L29-33)
```go
type CollectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}
```

**File:** model/flow/webauthn.go (L85-99)
```go
	clientData, err := decodedWebAuthnData.GetUnmarshalledCollectedClientData()
	if err != nil {
		return false, nil
	}

	// base64url decode the challenge, as that's the encoding used client side according to https://www.w3.org/TR/webauthn-3/#dictionary-client-data
	clientDataChallenge, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		return false, nil
	}

	if strings.Compare(clientData.Type, WebAuthnTypeGet) != 0 || len(clientDataChallenge) != webAuthnChallengeLength {
		// invalid client data
		return false, nil
	}
```

**File:** model/flow/webauthn.go (L121-127)
```go
	// extract rpIdHash, userFlags, sigCounter, extensions
	rpIdHash := decodedWebAuthnData.AuthenticatorData[:webAuthnChallengeLength]
	userFlags := decodedWebAuthnData.AuthenticatorData[webAuthnChallengeLength]
	extensions := decodedWebAuthnData.AuthenticatorData[webAuthnExtensionDataMinimumLength:]
	if bytes.Equal(TransactionDomainTag[:], rpIdHash) {
		return false, nil
	}
```

**File:** model/flow/transaction_test.go (L510-518)
```go
				description:       "empty origin (valid)",
				authenticatorData: validAuthenticatorData,
				clientDataJSON: map[string]string{
					"type":      flow.WebAuthnTypeGet,
					"challenge": authNChallengeBase64Url,
					"origin":    "",
				},
				extensionOk: true,
				signatureOk: true,
```

**File:** fvm/transactionVerifier.go (L62-88)
```go
func (entry *signatureContinuation) verify() errors.CodedError {
	if entry.invokedVerify {
		return entry.verifyErr
	}

	entry.invokedVerify = true

	valid, message := entry.ValidateExtensionDataAndReconstructMessage(entry.payload)
	if !valid {
		entry.verifyErr = entry.newError(fmt.Errorf("signature extension data is not valid"))
		return entry.verifyErr
	}

	valid, err := crypto.VerifySignatureFromTransaction(
		entry.Signature,
		message,
		entry.accountKey.PublicKey,
		entry.accountKey.HashAlgo,
	)
	if err != nil {
		entry.verifyErr = entry.newError(err)
	} else if !valid {
		entry.verifyErr = entry.newError(fmt.Errorf("signature is not valid"))
	}

	return entry.verifyErr
}
```

**File:** model/flow/transaction.go (L304-323)
```go
func (s TransactionSignature) ValidateExtensionDataAndReconstructMessage(payload []byte) (bool, []byte) {
	// Default to Plain scheme if extension data is nil or empty
	scheme := PlainScheme
	if len(s.ExtensionData) > 0 {
		scheme = AuthenticationSchemeFromByte(s.ExtensionData[0])
	}

	switch scheme {
	case PlainScheme:
		if len(s.ExtensionData) > 1 {
			return false, nil
		}
		return true, slices.Concat(TransactionDomainTag[:], payload)
	case WebAuthnScheme: // See FLIP 264 for more details
		return validateWebAuthNExtensionData(s.ExtensionData, payload)
	default:
		// authentication scheme not found
		return false, nil
	}
}
```
