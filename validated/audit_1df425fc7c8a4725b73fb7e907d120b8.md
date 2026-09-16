### Title
Improper path-prefix authorization check in arbiter dispute "mutual signing" verification allows bypass via crafted signing path - (File: wallet.js)

### Summary
In `handleMessageFromHub`'s handler for the `arbiter_dispute_request` device message, ocore verifies that a shared-address signing unit was "mutually signed" by both contract parties using a naive string-prefix check (`String.prototype.startsWith`) on signing paths instead of an exact/boundary-aware path match. This is the same bug class as the Formio advisory (CWE-178, improper path handling leading to permission elevation): a crafted path that merely shares a numeric prefix with the expected authorization path is treated as if it were nested under/equal to that path, letting a party satisfy an authorization check that should require a completely different signer.

### Finding Description [1](#0-0) 

```
const author = objUnit.authors.find(author => author.address === body.shared_address);
...
const signing_paths = Object.keys(author.authentifiers);
const isMutuallySigned = signing_paths.find(p => p.startsWith('r.0.0')) && signing_paths.find(p => p.startsWith('r.0.1'));
if (!isMutuallySigned)
    return callbacks.ifError(`signing unit ${body.unit} is not mutually signed, authentifiers: ${JSON.stringify(author.authentifiers)}`);
```

`isMutuallySigned` is intended to confirm that both the offeror branch (signing path `r.0.0`) and the acceptor branch (signing path `r.0.1`) of the shared address's `and`/`or` address definition tree actually authenticated the referenced unit, before the arbiter's wallet accepts a dispute request and proceeds to `arbiter_contract.insertDispute` (leading to arbitration/fund-release flow) [2](#0-1) .

Because `startsWith` performs a raw substring comparison with no path-boundary awareness (no check that the next character is `.` or end-of-string), any authentifier path that shares the digits `r.0.0` or `r.0.1` as a literal prefix is accepted as "belonging" to that branch — even though, in the dot-separated path tree used throughout `definition.js`/`validation.js`, sibling branches at the same nesting level are distinguished by full numeric tokens (e.g. `r.0.1` and `r.0.10` are different, unrelated branches, not one nested in the other). For example, a definition whose `and`/`or` node under `r.0` has 11 or more child options produces sibling branches `r.0.0`...`r.0.10`; a signature at path `r.0.10` will make `p.startsWith('r.0.1')` return true even though that signature has nothing to do with the acceptor's `r.0.1` branch.

This mirrors exactly the Formio flaw: a permission/authorization decision keyed off a raw path-prefix comparison, where a specially crafted path defeats the intended scoping and is accepted as authorized when it should not be. `ocore`'s own definition-evaluation code (`definition.js`) is aware that plain prefix matching over dotted paths is unsafe in general (`pathIncludesOneOfAuthentifiers` in `definition.js:31-40`) [3](#0-2) , but that internal helper is only used as a conservative "may contain a needed authentifier" pre-check before falling back to exact key lookups in `assocAuthentifiers[path]` for `sig`/`hash` ops, so a false positive there cannot forge a signature. The `wallet.js` check, however, is the final and only gate for the "mutual signing" business-logic decision — there is no subsequent exact-path verification, so a prefix collision here directly flips the decision from "not mutually signed" to "mutually signed."

### Impact Explanation
An attacker who controls (or colludes in creating) the shared address definition for an arbiter contract can craft a multi-branch address definition where a spurious signing path (e.g., `r.0.10`, `r.0.100`, etc.) exists as a legitimate, cryptographically valid signature location under the shared address (this is a normal 'or'/'and' branch, so a real signature there validates against the real definition during ordinary unit validation). By posting/obtaining a real, validly-signed unit that is authenticated only via that spurious branch — never via the genuine acceptor branch `r.0.1` — and then sending an `arbiter_dispute_request` referencing that unit, the malicious party causes the arbiter's wallet to conclude `isMutuallySigned === true` even though the actual counterparty (the acceptor) never authorized the unit. This lets a single party push a dispute into the arbiter's flow with unit data appearing "mutually agreed," undermining the intended 2-of-2 mutual-consent guarantee that the arbiter dispute mechanism relies on before an arbiter can act on a contract/escrowed payment.

### Likelihood Explanation
The `arbiter_dispute_request` message is explicitly reachable from a paired device (the arbstore) per the case comment "// arbstore sends to arbiter's wallet" [4](#0-3) , and the shared address / contract definition itself is attacker-influenced content created during contract setup, which is within the reach of a private-payment/contract counterparty. Building a definition with an 'or' branch containing 11+ options is straightforward, and obtaining a validly-signed unit under one specific branch requires only the attacker's own key, not the counterparty's. The check is a single overlooked `startsWith` call with no accompanying exact-path fallback, making this a purely logical flaw with no cryptographic hurdle once the crafted branch structure exists.

### Recommendation
Replace the `startsWith` prefix checks with boundary-aware comparisons, matching the exact path or the path followed by a `.` separator, e.g.:
```js
const isMine = p => p === 'r.0.0' || p.startsWith('r.0.0.');
const isPeer = p => p === 'r.0.1' || p.startsWith('r.0.1.');
const isMutuallySigned = signing_paths.some(isMine) && signing_paths.some(isPeer);
```
More robustly, derive the offeror/acceptor signing-path prefixes dynamically from the parsed `definition` (as is already done a few lines below for `offeror_address`/`acceptor_address`) rather than hardcoding `'r.0.0'`/`'r.0.1'`, and always compare with a trailing separator or exact equality to prevent sibling-branch collisions such as `r.0.1` vs `r.0.10`.

### Proof of Concept
1. Attacker (as offeror or a colluding party) creates a shared address for the arbiter contract whose definition includes, under the mutual `and`/`or` node, an 11-branch (or more) `or` list at the acceptor's position/sibling position such that a valid signing branch path `r.0.10` exists that is unrelated to the true acceptor branch `r.0.1`.
2. Attacker signs a unit using only branch `r.0.10` (a branch the attacker alone controls), producing `author.authentifiers = { "r.0.10": "<sig>", ... }` — this is a normal, validly verified signature for that branch per `Definition.validateAuthentifiers`.
3. Attacker (or colluding arbstore) sends `arbiter_dispute_request` with `body.unit` pointing to this unit.
4. In `wallet.js`, `signing_paths.find(p => p.startsWith('r.0.1'))` matches `"r.0.10"`, and if any authentifier also exists starting `r.0.0`, `isMutuallySigned` evaluates `true` despite the true acceptor path `r.0.1` never having signed.
5. The dispute request is accepted (`arbiter_contract.insertDispute`), proceeding as if the contract were genuinely mutually authorized, when in fact only one party's key authorized the referenced unit.

### Citations

**File:** wallet.js (L746-747)
```javascript
			// arbstore sends to arbiter's wallet
			case 'arbiter_dispute_request':
```

**File:** wallet.js (L811-817)
```javascript
					const author = objUnit.authors.find(author => author.address === body.shared_address);
					if (!author)
						return callbacks.ifError("shared address author not found in signing unit");
					const signing_paths = Object.keys(author.authentifiers);
					const isMutuallySigned = signing_paths.find(p => p.startsWith('r.0.0')) && signing_paths.find(p => p.startsWith('r.0.1'));
					if (!isMutuallySigned)
						return callbacks.ifError(`signing unit ${body.unit} is not mutually signed, authentifiers: ${JSON.stringify(author.authentifiers)}`);
```

**File:** wallet.js (L841-861)
```javascript
					// rejection is ok, the message will not be deleted from the hub
					const { device_address } = await arbiters.getArbstoreInfo(body.arbiter_address);
					if (device_address !== from_address)
						return callbacks.ifError("you are not my arbstore");

					body.contract_content = contractContent;
					body.arbstore_device_address = from_address;
					arbiter_contract.insertDispute(body, function(res) {
						if (res.affectedRows == 0) {
							return callbacks.ifError("can't insert dispute request into db");
						}
						var objDispute = {
							contract_hash: body.contract_hash,
							title: contractContent.title,
							service_fee_asset: body.service_fee_asset
						};
						var chat_message = "(arbiter-dispute:" + Buffer.from(JSON.stringify(objDispute), 'utf8').toString('base64') + ")";
						eventBus.emit("text", from_address, chat_message, ++message_counter);
						callbacks.ifOk();
					});
				});
```

**File:** definition.js (L31-40)
```javascript
function pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition){
	if (bAssetCondition)
		throw Error('pathIncludesOneOfAuthentifiers called in asset condition');
	for (var i=0; i<arrAuthentifierPaths.length; i++){
		var authentifier_path = arrAuthentifierPaths[i];
		if (authentifier_path.substr(0, path.length) === path)
			return true;
	}
	return false;
}
```
