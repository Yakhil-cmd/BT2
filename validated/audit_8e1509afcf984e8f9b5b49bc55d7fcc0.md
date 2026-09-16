### Title
Missing Wallet-Membership Authorization on `new_wallet_address` Device Message - (File: wallet.js)

### Summary
`handleMessageFromHub` in `wallet.js` accepts device-to-device protocol messages after only two checks: (1) the sender is a *known correspondent* (or on an explicit non‑correspondent whitelist) in `device.js`, and (2) format/type validation of the message body. For most state‑changing subjects (e.g. `arbiter_contract_shared`, `arbiter_contract_update`, `prosaic_contract_shared`) the handler additionally re‑verifies that the acting `from_address` is actually entitled to touch the referenced resource (a shared address, a contract hash, etc.) before mutating local state. The `new_wallet_address` case does not do this: it forwards the attacker‑controlled `body.wallet` identifier straight into `walletDefinedByKeys.addNewAddress()` without ever checking that `from_address` is a registered cosigner/device of that `wallet`.

### Finding Description
In `handleMessageFromHub`, the `new_wallet_address` subject only validates field *shape*, not *ownership*: [1](#0-0) 

Compare this to the sibling handlers in the same switch statement, which explicitly re-derive and check `from_address` against `my_addresses`/`wallet_signing_paths`/`shared_address_signing_paths` before trusting the payload, e.g. the `arbiter_contract_shared` handler: [2](#0-1) 
and the `arbiter_contract_update` handler which explicitly rejects the request with `"not an owner"` if `from_address` doesn't match the expected party: [3](#0-2) 

By contrast, `new_wallet_address` passes `body.wallet` (an attacker‑supplied base64 string) directly into `walletDefinedByKeys.addNewAddress(body.wallet, body.is_change, body.address_index, body.address, …)` without passing `from_address` at all, so the callee has no way to confirm the sender is actually one of the wallet's registered devices (`extended_pubkeys`/`wallet_signing_paths` for that `wallet`) before the address record is written.

This is structurally the same bug class as the Dokploy issue: the outer layer authenticates the caller (`validateRequest` in Dokploy / correspondent check in `handleJustsaying`'s `hub/message` case, `device.js:204-221`), but a specific handler trusts a resource identifier supplied by the caller (`containerId` in Dokploy / `wallet` in ocore) without verifying the caller's authorization over that specific resource before performing a privileged write.

I was not able to fully inspect the body of `walletDefinedByKeys.addNewAddress()` itself (only its call sites and neighboring functions such as `addWallet`, `addDeviceXPubKey`, `deleteWallet` were retrieved), so I cannot 100% confirm whether that function internally re-derives/validates `wallet` ownership from other state before the `INSERT`. This is a genuine gap in my verification and should be checked directly in the file before treating this as conclusively exploitable.

### Impact Explanation
If `addNewAddress` does not itself re-verify wallet membership (consistent with the absence of `from_address` being passed to it, unlike other handlers that pass and check it), any paired correspondent (or any device reachable via the non‑correspondent whitelist for related subjects) who learns or guesses a victim's `wallet` identifier could inject or overwrite an `is_change`/`address_index` → `address` mapping in the victim's `my_addresses`-derived records for a wallet they are not a member of. Depending on how the wallet UI subsequently consumes this mapping (e.g., "next receiving address" selection or gap-limit address generation), this could cause the victim's software to display/use an attacker-chosen address for receiving funds, leading to funds being redirected to an address the attacker controls — a concrete unauthorized-spending/fund-diversion outcome.

### Likelihood Explanation
Reaching this code path requires only being a paired correspondent device of the victim (a low bar — pairing codes are often shared out-of-band and multi-wallet users routinely pair with several counterparties), and knowing/guessing the target `wallet` id (a SHA-256-derived base64 string tied to an xpubkey — not secret by design in multi-device wallet setups, since it's exchanged during wallet creation between cosigners). No user interaction beyond normal device-message delivery is required, matching the report's `UI:N` characteristic.

### Recommendation
In `wallet.js`, before calling `walletDefinedByKeys.addNewAddress()` for the `new_wallet_address` subject, verify that `from_address` is a legitimate device member of `body.wallet` (e.g., `SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?` or equivalent membership check against `wallet_signing_paths`), mirroring the ownership checks already present in the `arbiter_contract_shared`/`arbiter_contract_update`/`prosaic_contract_shared` handlers. Additionally, confirm and, if missing, add the same membership check inside `walletDefinedByKeys.addNewAddress()` itself so the guarantee doesn't rely solely on call-site discipline.

### Proof of Concept
Conceptual (not verified end-to-end due to inability to inspect `addNewAddress`'s full body):
1. Attacker device pairs with victim device as a normal correspondent (or is already a correspondent from prior interaction).
2. Attacker learns/guesses the victim's `wallet` id (exchanged during any prior multi-device wallet setup, or via other side channels).
3. Attacker sends a `new_wallet_address` device message:
   ```
   { subject: "new_wallet_address",
     body: { wallet: "<victim_wallet_base64>", is_change: 0, address_index: <N>, address: "<ATTACKER_ADDR>" } }
   ```
4. `wallet.js` (`wallet.js:180-195`) validates only field types/format and calls `walletDefinedByKeys.addNewAddress()` with no verification that the attacker device is a member of `<victim_wallet_base64>`.
5. If `addNewAddress` persists this mapping without its own ownership check, the victim's wallet client may subsequently offer/use `<ATTACKER_ADDR>` as address index `N` for that wallet, resulting in future payments being sent to the attacker's address instead of the victim's.

### Citations

**File:** wallet.js (L180-195)
```javascript
			case "new_wallet_address":
				// {wallet: "base64", is_change: (0|1), address_index: 1234, address: "BASE32"}
				if (!ValidationUtils.isNonemptyString(body.wallet))
					return callbacks.ifError("no wallet");
				if (!(body.is_change === 0 || body.is_change === 1))
					return callbacks.ifError("bad is_change");
				if (!ValidationUtils.isNonnegativeInteger(body.address_index))
					return callbacks.ifError("bad address_index");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				walletDefinedByKeys.addNewAddress(body.wallet, body.is_change, body.address_index, body.address, function(err){
					if (err)
						return callbacks.ifError(err);
					callbacks.ifOk();
				});
				break;
```

**File:** wallet.js (L658-678)
```javascript
			case 'arbiter_contract_shared':
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.peer_pairing_code || !ValidationUtils.isPositiveInteger(body.amount))
					return callbacks.ifError("not all contract fields submitted");
				if (!ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.arbiter_address) )
					return callbacks.ifError("either peer_address or address or arbiter_address or shared_address are not valid in contract");
				if (body.hash !== arbiter_contract.getHash(body))
					return callbacks.ifError("wrong contract hash");
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
				db.query("SELECT 1 FROM my_addresses \n\
						JOIN wallet_signing_paths USING(wallet)\n\
						WHERE my_addresses.address=? AND wallet_signing_paths.device_address=?",[body.my_address, from_address],
					function(rows) {
						if (!rows.length)
							return callbacks.ifError("contract does not contain my address shared with your device");
						body.me_is_cosigner = true;
						arbiter_contract.store(body, true);
						callbacks.ifOk();
					}
				);
				break;
```

**File:** wallet.js (L681-691)
```javascript
			case 'arbiter_contract_update':
				if (!ValidationUtils.isNonemptyString(body.hash))
					return callbacks.ifError("no contract hash");
				arbiter_contract.getByHash(body.hash, function(objContract){
					if (!objContract)
						return callbacks.ifError("wrong contract hash");
					db.query("SELECT 1 FROM wallet_signing_paths JOIN my_addresses USING(wallet) WHERE device_address=? AND address=?", [from_address, objContract.my_address], function(rows) {
						const from_cosigner = (rows.length && objContract.me_is_cosigner);
						if (from_address !== objContract.peer_device_address && !from_cosigner && !(from_address === objContract.arbstore_device_address && objContract.status === 'in_appeal' && body.field === 'status'))
							return callbacks.ifError("not an owner");
						if (body.field === "status") {
```
