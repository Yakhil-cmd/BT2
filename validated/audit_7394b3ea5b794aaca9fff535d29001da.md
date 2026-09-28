### Title
Position NFT can be transferred to a contract address that can never authorize, permanently freezing the lending position - (File: contracts/position-nft/src/contract.rs)

### Summary
The position NFT exports the stock OpenZeppelin `transfer`/`transfer_from` with no guard on the recipient. On Soroban a contract `Address` can only produce `require_auth` authorizations if it implements a custom account (`__check_auth`). A user who calls `transfer(from, to, token_id)` with `to` set to an ordinary contract address moves `owner_of(token_id)` to that contract, and since `account_id == token_id`, every owner-gated controller verb (`withdraw`, `repay`, `borrow`, `liquidate`-as-owner, `burn` on close) becomes unreachable. The collateral and debt carried by the account are frozen permanently — the exact analog of the FrankenDAO M-3 "NFT frozen in a contract that does not support ERC721" class, except Soroban offers no `onERC721Received`-style receiver hook to mitigate it.

### Finding Description
`PositionNft` inherits `transfer` and `transfer_from` unchanged from the `NonFungibleToken` trait (`contracts/position-nft/src/contract.rs:131-133`), and the README confirms they are "exported unchanged" (`contracts/position-nft/README.md:56-63`). Neither performs any check that `to` is an address capable of future authorization. Because transferring the token "transfers the whole position" (`README.md:39-41`) and the controller keys solvency/accounting on `account_id` resolved through `owner_of`, control of the account requires the *owner address* to authorize controller calls. A contract address without a `__check_auth` implementation can never produce such an authorization and cannot call `transfer` to move the token back out, so the position — collateral, debt, and any unclaimed yield — is bricked. The integration flow `tests/integration/flows/nft.sh:33-42` shows the token carries withdrawable collateral directly.

### Impact Explanation
Permanent freezing of user funds: all supplied collateral and any yield in the account become unreachable; the debt can never be repaid by the owner, and if the account later goes underwater it can still be liquidated by third parties but the residual collateral remains locked. No recovery path exists short of a governance upgrade of the NFT contract.

### Likelihood Explanation
Reachable by any unprivileged holder via `position_nft.transfer` / `transfer_from` with a contract `to` address. It requires user error (or a UI integrating a contract recipient such as a multisig/DAO wallet that lacks `__check_auth`), so likelihood is moderate — matching the original report's Medium severity. Smart-wallet integrations make contract recipients plausible rather than exotic.

### Recommendation
Reject transfers to contract addresses that cannot later act: at minimum, check `to` is not a contract address (or require the recipient contract to implement a receiver/acknowledgement hook invoked during `transfer`), and document that contract recipients must implement `__check_auth`. Alternatively add a controller-side escape hatch (e.g., governance-initiated recovery transfer) for bricked positions.

### Proof of Concept
```rust
// Alice holds account_id = token_id = 1 backed by supplied USDC.
// DUMB is a deployed contract address with no __check_auth / no transfer method.
position_nft::PositionNftClient::new(&env, &nft)
    .transfer(&alice, &dumb_contract, &1);
// owner_of(1) == dumb_contract.
// dumb_contract can never require_auth, so:
//   controller.withdraw(caller=dumb_contract, account_id=1, ...) -> NotAuthorized forever
//   position_nft.transfer(dumb_contract, alice, 1)               -> host auth error forever
// Collateral is permanently frozen.
```
Root cause: `NonFungibleToken`/`NonFungibleEnumerable` trait impl at `contract.rs:131-173` exports stock OZ transfers with no recipient validation.