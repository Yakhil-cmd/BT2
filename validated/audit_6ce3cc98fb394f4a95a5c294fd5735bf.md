### Title
Parameterized AA `base_aa` is an unrestricted attacker-controlled address that fully dictates fund handling for anyone paying into it - ([File: aa_validation.js], [File: aa_composer.js])

### Summary
Obyte's Autonomous Agents support "parameterized AA" definitions of the form `{ base_aa: <address>, params: {...} }`. When a trigger unit sends funds to a parameterized AA address, `handleTrigger()` transparently redirects execution to whatever AA sits at `base_aa`, and that base AA's logic decides how the received funds are disposed of. The only validation performed on `base_aa` is that it is a syntactically valid address - there is no whitelist, no check that it matches a known/audited template, and no enforcement that its `messages`/parameter usage matches what a depositor expects. This mirrors the reported Sablier issue: an address parameter that is fully trusted to safely custody and forward funds can be swapped for an arbitrary (malicious or mismatched) contract, without alerting the depositor.

### Finding Description
When validating an AA definition, if `template.base_aa` is present the code treats the AA as "parameterized" and only checks: [1](#0-0) 

No check is made that `base_aa` belongs to a whitelist of vetted/known-good base AAs, nor that its `params` usage/types match the depositor's expectations - directly analogous to the Sablier factory accepting arbitrary `LockupLinear`/`LockupTranched` addresses "as long as it supports the required functions."

At execution time, when a unit is sent to the parameterized AA's address, `handleTrigger()` fetches `base_aa`'s definition and re-dispatches the *entire* trigger handling to it, inheriting all of its payment/message logic: [2](#0-1) 

Because the parameterized AA's address is `objectHash.getChash160(['autonomous agent', {base_aa, params}])`, a user cannot tell from the address alone whether `base_aa` is the legitimate, audited template they expect or a lookalike/malicious AA deployed by an attacker (or an insider on a team that publishes such addresses to users, exactly the "team member" abuse scenario in the report). Anyone can deploy a malicious `base_aa` whose `messages` payment outputs route funds to an attacker-controlled address (e.g., ignoring `trigger.address`/`trigger.initial_address` and instead paying a hardcoded address), then advertise a parameterized AA pointing to it as if it were a standard vault/vesting/exchange contract.

### Impact Explanation
Any user or protocol that sends bytes/assets to a parameterized AA address, trusting that its behavior follows a known/audited `base_aa` template, can have their funds unconditionally redirected to an attacker address chosen by whoever set `base_aa`, since the recipient of a "payment" message inside the base AA's logic is entirely at the discretion of that base AA's author. This is an unauthorized-fund-loss vector reachable by any unprivileged AA author who publishes/promotes a parameterized AA definition, matching the "concrete unauthorized spending" / "AA fund loss" criteria.

### Likelihood Explanation
Deploying a parameterized AA definition and a malicious base AA is trivial and requires no special privilege - it's a normal `definition` message any address can post, validated purely by the generic checks in `aa_validation.js`. The only barrier is social: convincing users/counterparties that a given parameterized AA address is trustworthy (e.g., by claiming it uses a well-known base AA while actually using a subtly different one), which is precisely the class of risk the Sablier report describes for lockup factories.

### Recommendation
- Consider surfacing `base_aa` prominently in wallets/UIs whenever a user is about to send funds to a parameterized AA, and warn if `base_aa` is not a recognized/whitelisted template.
- For protocols building on top of parameterized AAs (analogous to Sablier's factory), maintain and check against a whitelist of vetted `base_aa` addresses rather than trusting user- or third-party-supplied addresses at face value.
- Consider adding stronger static/type validation between a `base_aa`'s expected `params` and the values supplied by a parameterized AA, so mismatched templates fail closed rather than executing with unexpected parameter types.

### Proof of Concept
1. Attacker deploys `malicious_base_aa`, an AA whose `payment` message pays out to `ATTACKER_ADDRESS` regardless of `trigger.address`:
```
['autonomous agent', {
  messages: [{
    app: 'payment',
    payload: {
      asset: 'base',
      outputs: [{ address: 'ATTACKER_ADDRESS', amount: "{trigger.output[[asset=base]] - 1000}" }]
    }
  }]
}]
```
2. Attacker creates a parameterized AA `{ base_aa: malicious_base_aa_address, params: {...} }`, whose derived address they present to victims as a legitimate vesting/vault contract (mirroring how a malicious `LockupLinear`/`LockupTranched` address is passed to `createMerkleLL/LT`).
3. Victim sends funds to the parameterized AA address, unaware that `handleTrigger()` will delegate execution entirely to `malicious_base_aa` per [2](#0-1) .
4. Funds are paid out to `ATTACKER_ADDRESS` instead of returned/vested to the victim, since nothing in `aa_validation.js` restricts which `base_aa` may be referenced.

### Citations

**File:** aa_validation.js (L734-744)
```javascript
	if (template.base_aa) { // parameterized AA
		if (hasFieldsExcept(template, ['base_aa', 'params']))
			return callback("foreign fields in parameterized AA definition");
		if (!isNonemptyObject(template.params))
			return callback("no params in parameterized AA");
		if (!variableHasStringsOfAllowedLength(template.params))
			return callback("some strings in params are too long");
		if (!isValidAddress(template.base_aa))
			return callback("base_aa is not a valid address");
		return callback(null);
	}
```

**File:** aa_composer.js (L433-444)
```javascript
	if (template.base_aa) { // parameterized AA
		if (params && Object.keys(params).length > 0)
			throw Error("unexpected params");
		storage.readAADefinition(conn, template.base_aa, mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + template.base_aa);
			console.log("redirecting to base AA " + template.base_aa + " with params " + JSON.stringify(template.params));
			trigger_opts.params = template.params;
			trigger_opts.arrDefinition = arrBaseDefinition;
			handleTrigger(trigger_opts);
		});
		return;
```
