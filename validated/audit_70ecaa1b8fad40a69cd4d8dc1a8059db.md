### Title
Base-currency (bytes) balance on a claimed private-asset textcoin is not forwarded to the recipient, trapping funds on an unmanaged address - (File: wallet.js)

### Summary
The external report describes a bridge contract that transfers a base asset (native currency) to a bridge address but the recipient-forwarding logic only handles the bridged token, permanently trapping the base asset. The analogous class of bug (a routine that "claims"/forwards value from an intermediate address to a real recipient, but only forwards one asset type while silently leaving the base currency behind) is reachable in ocore through the textcoin-claiming logic in `receiveTextCoin` in `wallet.js`.

### Finding Description
`receiveTextCoin()` lets any recipient claim funds sitting on a deterministic address derived from a textcoin mnemonic (`expandMnemonic`) [1](#0-0) . When the address holds an asset (not plain bytes), `checkStability()` branches on whether the asset is public or private [2](#0-1) :

- For a **public (non-private) asset**, the code explicitly builds `outputs_by_asset` covering every asset row **and** adds `outputs_by_asset.base = [{ amount: 0, address: addressTo }]`, with the comment "the change goes to our wallet, not being left on the textcoin" [3](#0-2) . This correctly routes any leftover base-currency change to the real recipient (`addressTo`).
- For a **private asset**, only `opts.asset`, `opts.amount`, and `opts.to_address = addressTo` are set; no equivalent base-currency forwarding is configured [4](#0-3) . The comment acknowledges this: "otherwise the change goes back to the fee paying address as we don't want to publish the recipient address" [5](#0-4) .

`opts.fee_paying_addresses` is then set to `[addrInfo.address]` — i.e., the textcoin address itself, not `addressTo` [6](#0-5) . Down in `composeDivisibleAssetPaymentJoint`, when no explicit `base_outputs`/`outputs_by_asset.base` zero-change output is supplied, the base-currency change output defaults to `params.fee_paying_addresses[0]`, i.e. the original textcoin address, not the recipient:
```js
var arrBaseOutputs = bAlreadyHaveChange ? [] : [{address: params.fee_paying_addresses[0], amount: 0}]; // public outputs: the change only
``` [7](#0-6) 

The consequence mirrors the reported bug exactly: when a message/unit carries a mixed transfer (private token + base bytes) to an address that is then "claimed"/forwarded on behalf of a recipient, the forwarding logic transfers only the token and leaves the base currency behind on the intermediate address instead of the actual recipient.

### Impact Explanation
Any bytes sitting alongside a private-asset textcoin (e.g., bytes the sender attached to help the recipient pay future fees, or leftover UTXO dust) are not delivered to `addressTo`. They remain on `addrInfo.address`, a raw one-off `["sig", {pubkey}]` address that is never added to the recipient's `my_addresses`/wallet tracking (the recipient wallet only remembers the derived signer transiently inside `receiveTextCoin`, it does not persist the address as owned). From the recipient's UI/wallet perspective these bytes are invisible and unspendable through normal flows, and the periodic sweep `claimBackOldTextcoins()` only targets addresses that were *never* used (`unit_authors.address IS NULL`) [8](#0-7) ; once the private-asset claim transaction consumes an input from that address, it now has a `unit_authors` row and is excluded from that recovery sweep, so the leftover base-currency balance is not automatically reclaimed by anyone. This is a fund-freezing bug reachable by an ordinary user (private-payment counterparty claiming a textcoin), matching the "private payment chains" and "wallet ... message handling" categories in scope.

### Likelihood Explanation
This triggers deterministically any time: (1) someone sends a private (is_private) divisible or indivisible asset as a textcoin, and (2) any base-currency bytes are also present as an unspent output on that same mnemonic-derived address (a realistic scenario since textcoins commonly carry extra bytes to cover future claim fees, or leftover change from asset issuance/composition). No attacker cooperation is required — it is an unconditional code path for every private-asset textcoin claim, so likelihood is high whenever this feature (private textcoins) is used with attached bytes.

### Recommendation
Mirror the public-asset handling for private assets while preserving privacy: instead of defaulting the base-currency change output to `fee_paying_addresses[0]` (the exposed textcoin/mnemonic address), give the caller an explicit path to route the leftover base currency to a private/blinded output to `addressTo`, or explicitly persist `addrInfo.address` as a wallet-owned address after a successful private claim so the wallet UI can track and let the user later sweep the residual bytes. At minimum, document/flag the residual balance so it is not silently unrecoverable, and extend `claimBackOldTextcoins` (or an equivalent sweep) to also cover addresses that still hold an unclaimed base-currency remainder after a private-asset claim.

### Proof of Concept
1. Alice creates a private-asset textcoin: she funds a fresh mnemonic-derived address with, say, 5,000 bytes of the private asset plus 2,000 extra base bytes (to help Bob pay claim fees), and shares the mnemonic with Bob.
2. Bob calls `wallet.receiveTextCoin(mnemonic, addressTo, ...)`. `checkStability()` finds `rows` containing both the private-asset row and a base-currency row; since `objAsset.is_private` is true, only `opts.asset/opts.amount/opts.to_address = addressTo` are set [4](#0-3) , and `opts.fee_paying_addresses = [addrInfo.address]` [6](#0-5) .
3. `divisibleAsset.composeAndSaveDivisibleAssetPaymentJoint` is invoked; because no `base_outputs`/`outputs_by_asset.base` zero-output was supplied, the base-currency change output defaults to `params.fee_paying_addresses[0]` = `addrInfo.address` [9](#0-8) .
4. The private asset amount arrives at Bob's `addressTo`, but the leftover base bytes remain on `addrInfo.address`, an address Bob's wallet never records as its own — those bytes are not shown in Bob's balance and are not reachable through the normal wallet claim/sweep flow.

**Note:** This is a design-level trade-off explicitly acknowledged in the code comment ("we don't want to publish the recipient address"), so its classification as a "vulnerability" versus an accepted privacy/UX trade-off could not be fully confirmed from static code reading alone; a Devin session with the full app/wallet-UI code and test suite would be needed to verify whether any other code path actually recovers or displays this residual balance to the user.

### Citations

**File:** wallet.js (L2643-2655)
```javascript
function expandMnemonic(mnemonic) {
	var addrInfo = {};
	mnemonic = mnemonic.toLowerCase().split('-').join(' ');
	if ((mnemonic.split(' ').length % 3 !== 0) || !Mnemonic.isValid(mnemonic)) {
		throw new Error("invalid mnemonic: "+mnemonic);
	}
	mnemonic = new Mnemonic(mnemonic);
	addrInfo.xPrivKey = mnemonic.toHDPrivateKey().derive("m/44'/0'/0'/0/0");
	addrInfo.pubkey = addrInfo.xPrivKey.publicKey.toBuffer().toString("base64");
	addrInfo.definition = ["sig", {"pubkey": addrInfo.pubkey}];
	addrInfo.address = objectHash.getChash160(addrInfo.definition);
	return addrInfo;
}
```

**File:** wallet.js (L2749-2770)
```javascript
				var row = rows[0];
				if (row.asset) { // claiming asset
					const assets = rows.map(row => row.asset).filter(a => a);
					const { unknown_assets, asset_infos } = await getAssetInfos(assets);
					if (unknown_assets.length > 0 && conf.bLight)
						return network.requestHistoryFor(unknown_assets, [], checkStability);
					asset = assets[0];
					const objAsset = asset_infos[0]; // assuming all other assets have the same privacy and divisibility
					if (!objAsset.is_private) { // otherwise the change goes back to the fee paying address as we don't want to publish the recipient address
						let outputs_by_asset = { };
						for (let { asset, amount } of rows)
							if (asset)
								outputs_by_asset[asset] = [{ amount, address: addressTo }];
						outputs_by_asset.base = [{ amount: 0, address: addressTo }]; // the change goes to our wallet, not being left on the textcoin
						opts.outputs_by_asset = outputs_by_asset;
					}
					else { // claim only the 1st asset
						opts.asset = asset;
						opts.amount = row.amount;
						opts.to_address = addressTo;
						opts._private = true; // to prevent retries with fees paid by the recipient
					}
```

**File:** wallet.js (L2771-2772)
```javascript
					if (!opts.fee_paying_addresses)
						opts.fee_paying_addresses = [addrInfo.address];
```

**File:** wallet.js (L2818-2839)
```javascript
function claimBackOldTextcoins(to_address, days){
	if (typeof days !== 'number')
		throw Error("bad days: " + days);
	db.query(
		"SELECT mnemonic FROM sent_mnemonics LEFT JOIN unit_authors USING(address) \n\
		WHERE mnemonic!='' AND unit_authors.address IS NULL AND creation_date<"+db.addTime("-"+days+" DAY"),
		function(rows){
			async.eachSeries(
				rows,
				function(row, cb){
					receiveTextCoin(row.mnemonic, to_address, function(err, unit, asset){
						if (err)
							console.log("failed claiming back old textcoin "+row.mnemonic+": "+err);
						else
							console.log("claimed back mnemonic "+row.mnemonic+", unit "+unit+", asset "+asset);
						cb();
					});
				}
			);
		}
	);
}
```

**File:** divisible_asset.js (L202-211)
```javascript
	let bAlreadyHaveChange = false;
	if (params.base_outputs && params.base_outputs.find(o => o.amount === 0))
		bAlreadyHaveChange = true;
	if (params.outputs_by_asset && params.outputs_by_asset.base && params.outputs_by_asset.base.find(o => o.amount === 0))
		bAlreadyHaveChange = true;
	var arrBaseOutputs = bAlreadyHaveChange ? [] : [{address: params.fee_paying_addresses[0], amount: 0}]; // public outputs: the change only
	if (params.base_outputs)
		arrBaseOutputs = arrBaseOutputs.concat(params.base_outputs);
	if (params.outputs_by_asset && params.outputs_by_asset.base)
		arrBaseOutputs = arrBaseOutputs.concat(params.outputs_by_asset.base);
```
