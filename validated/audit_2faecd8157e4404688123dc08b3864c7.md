### Title
Seller can drain a position's collateral and load it with debt immediately before transferring the position NFT - ([File: contracts/controller/src/storage/account.rs](contracts/controller/src/storage/account.rs))

### Summary
A lending position in XOXNO is a transferable NFT (`contracts/position-nft`), and every owner-gated controller verb (`withdraw`, `borrow`, `swap_collateral`, etc.) resolves authority via a live `owner_of(account_id)` lookup. Nothing in the protocol locks, escrows, or snapshots the account when a sale/transfer of the NFT is pending on a marketplace. A seller can therefore keep full control of the account until the transfer executes and, in a prior transaction (or a preceding operation in the same transaction via `transfer_from` approval), withdraw all withdrawable collateral and borrow up to the LTV limit to their own address. The buyer receives the NFT holding a maximally leveraged, near-HF=1 husk instead of the collateralized position advertised.

### Finding Description
The controller stores no owner cache: `try_account_owner` resolves `nft_try_owner_of_call` on every call, so until the NFT actually moves, the seller remains fully authorized. `withdraw(caller, account_id, withdrawals, to)` pays out to `to` (or the caller) subject only to the post-action HF ≥ 1 check, and `borrow(caller, account_id, borrows, to)` sends the newly minted debt proceeds to `to` (defaulting to the caller) while the debt stays booked on the account. Because collateral and debt both travel with the token, the seller can extract the account's entire equity — withdraw all collateral down to the solvency boundary and borrow to the cap — and then let the marketplace `transfer`/`transfer_from` execute. The victim pays the agreed price for an NFT whose economic value was just removed. This is structurally identical to the Footium escrow drain: the assets backing the NFT are controlled by the *current* owner with no coupling to an in-flight transfer.

### Impact Explanation
Theft of buyer funds: the buyer pays market price for a position that has been stripped of withdrawable collateral and stuffed with debt. The extracted tokens leave the protocol to the seller's chosen `to` recipient; there is no recovery path. Loss is bounded by the account's equity (collateral minus debt at max LTV), which can be arbitrarily large.

### Likelihood Explanation
Requires a marketplace/OTC sale where settlement (`transfer`/`transfer_from`) is not atomic with a state freeze, which is the normal case for NFT trades. The seller signs an approval once and can front-run the settlement transaction at will — `withdraw` is even callable during global pause. Position state is public, so a vigilant buyer could re-check, but the attack costs the seller only one transaction and needs no special privilege.

### Recommendation
Couple control of the account to pending ownership transfer, e.g.: (a) burn/clear per-token approvals automatically is already done — extend that to freezing owner-gated asset-out verbs while a token has an active `get_approved` or pending marketplace listing, or (b) provide an atomic "transfer with state assertion" where the transfer specifies expected collateral/debt snapshots and reverts if `withdraw`/`borrow` changed them, or (c) settle sales through a protocol-aware escrow that holds the NFT while its account is locked.

### Proof of Concept
1. Alice supplies 10,000 USDC to a new account via `supply(Alice, 0, spoke, [(key, 10_000e7)])`; receives position NFT `id` backed by 10,000 USDC collateral.
2. Alice lists the NFT for sale; Bob agrees to buy, expecting the collateralized position. Marketplace executes `transfer_from(market, Alice, Bob, id)`.
3. Alice front-runs (or sandwiches inside her own batched transaction): `borrow(Alice, id, [(debt_key, maxBorrowable)], Some(Alice))` — proceeds go to Alice, debt books to `id`; then `withdraw(Alice, id, [(usdc_key, excess)], Some(Alice))` down to HF = 1.
4. Bob's settlement lands: `owner_of(id) == Bob`. Bob now holds an account with minimal net equity and a large debt; Alice keeps the borrowed tokens and withdrawn collateral plus Bob's payment.