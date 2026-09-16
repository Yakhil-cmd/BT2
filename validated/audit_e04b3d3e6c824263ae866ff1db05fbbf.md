### Title
Autonomous Agents Can Permanently Trap Private-Asset Payments Sent to Them - ([File: aa_composer.js])

### Summary
The external report describes an `early-purchase` Solana program that could receive buyer payments but had no mechanism to move those payments out of the program's PDA — collected funds became permanently stuck with no withdrawal path. The analogous bug class in `ocore` is that an Autonomous Agent (AA), which is a program-controlled address that receives triggers, has no way to ever forward or spend a private (hidden-payment) asset that it receives, even though nothing in unit validation prevents an unprivileged user from sending such an asset to an AA as a trigger payment.

### Finding Description
When an AA composes its response unit, it iterates over the payment messages it wants to send. For any asset payment it wants to make, it loads the asset's properties and explicitly refuses to send it if the asset `is_private`: [1](#0-0) 

The comment on that line ("it'll fail validation anyway due to lack of spend_proofs") documents *why* — AAs are not interactive parties and cannot produce spend proofs for private (hidden) coin transfers, which require cooperative reveal of blinding factors between sender and receiver over private channels. Because of this structural limitation, once a private asset is credited to an AA's balance, the AA can never issue a payment message to move it back out. There is no other code path in `aa_composer.js` that allows an AA to release private-asset funds (e.g., via a separate "withdraw" message type or an exception for returning private assets to the sender).

Nothing in unit/payment validation (`validation.js`, `validatePayment`) prevents an ordinary unprivileged user from sending a private-asset payment chain to an AA address as part of a trigger — an AA address is simply a normal address as far as `validatePaymentInputsAndOutputs` and asset-transfer-condition checks are concerned.

### Impact Explanation
Any private asset (an asset defined with `is_private: true`) sent to an AA address by mistake, by a malicious or naive counterparty, or as part of a private-payment chain, becomes permanently unspendable by the AA. This is a form of AA fund loss/freezing: value that is credited to the AA's on-chain balance can never be withdrawn or forwarded by AA logic, regardless of what the AA's `oscript` intends to do (e.g., refund the sender, forward to a treasury, or record and later disburse). This mirrors the reported bug class exactly — payments are received into a program-controlled account but the program has no way to transfer them out — except here it is not a fixable application logic gap but an intrinsic limitation of the AA execution model for private assets, silently trapping any private-asset funds an AA receives.

### Likelihood Explanation
Likelihood is limited to scenarios where a private asset happens to be sent to an AA address (private assets are less commonly used than public/base-currency assets in practice, and sending to an AA requires the sender to know/target an AA address for a private-asset transfer). However, since there is no automatic protocol-level check preventing users from sending private assets to AAs, and private-asset definitions/transfers are a first-class, unprivileged-reachable feature (`asset` messages, private payment chains), any unprivileged asset issuer/holder can trigger this freeze condition against an AA, whether by mistake or intentionally to trap value or grief AA state accounting that assumes recoverability of received funds.

### Recommendation
- At the unit-validation layer, reject payments of `is_private` assets when the recipient (payment output address) is a known AA address, so such payments never get accepted/stabilized in the first place (similar in spirit to the existing `checkNotAAs` check used for other cases).
- Alternatively/additionally, document this limitation clearly for AA authors and provide a supported mechanism (e.g., a light-client/wallet warning, or a protocol-level bounce) so that private-asset payments sent to AA addresses are bounced back to the sender rather than silently accepted and permanently locked.

### Proof of Concept
1. Define a private, non-fixed-denomination asset compliant with the private-asset rules enforced in `validateAssetDefinition` (e.g., `is_private: true`, `auto_destroy: true`, `is_transferrable: false`), owned/issued by an ordinary user address.
2. As an unprivileged user, initiate a private payment chain sending units of this asset to an existing AA's address (this passes normal `validatePayment`/`validatePaymentInputsAndOutputs` checks — private-asset transfer to an AA address is not specially disallowed).
3. Once the payment stabilizes, the AA's balance for that asset is credited.
4. Trigger the AA in any way that would cause it to attempt to forward/return that asset (e.g., an oscript rule that tries to send the received asset back to `trigger.address`).
5. Observe in `aa_composer.js` (line 1329-1330) that the AA response composition immediately fails with `"sending private asset from AA"` for any payment message referencing that asset — the AA can never construct a valid outgoing payment for it.
6. The private-asset balance remains permanently stuck in the AA's address with no available code path (in `aa_composer.js` or elsewhere) to release it.

### Citations

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```
