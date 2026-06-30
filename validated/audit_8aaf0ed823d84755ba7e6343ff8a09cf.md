### Title
Missing Zero-Address Check in `AdminControlled` Constructor Permanently Locks `EvmErc20`/`EvmErc20V2` Admin Functions - (File: `etc/eth-contracts/contracts/AdminControlled.sol`)

---

### Summary

`AdminControlled.sol` accepts `_admin` in its constructor without validating it is non-zero. Both `EvmErc20` and `EvmErc20V2` inherit from `AdminControlled` and forward the `admin` constructor argument directly. If `admin` is set to `address(0)`, all `onlyAdmin`-gated functions — including `mint` — become permanently inaccessible, freezing the token's minting capability and permanently breaking the bridge for that token.

---

### Finding Description

`AdminControlled.sol` constructor assigns `_admin` without any zero-address guard:

```solidity
constructor(address _admin, uint flags) {
    // slither-disable-next-line missing-zero-check
    admin = _admin;
    paused = flags;
}
``` [1](#0-0) 

The `// slither-disable-next-line missing-zero-check` comment explicitly acknowledges the missing validation but suppresses the warning rather than fixing it.

Both `EvmErc20` and `EvmErc20V2` inherit `AdminControlled` and pass the `admin` constructor argument directly without any prior validation:

```solidity
constructor (string memory metadata_name, string memory metadata_symbol, uint8 metadata_decimals, address admin)
    ERC20(metadata_name, metadata_symbol)
    AdminControlled(admin, 0)
``` [2](#0-1) [3](#0-2) 

The `onlyAdmin` modifier enforces `require(msg.sender == admin)`: [4](#0-3) 

If `admin == address(0)`, no EOA or contract can ever satisfy `msg.sender == address(0)`, making all `onlyAdmin` functions permanently unreachable. The critical affected function is `mint`:

```solidity
function mint(address account, uint256 amount) public onlyAdmin {
    _mint(account, amount);
}
``` [5](#0-4) 

`mint` is the sole mechanism by which the Aurora Engine credits bridged ERC-20 tokens to users on the Aurora EVM side. If it is permanently locked, no tokens can ever be minted for that ERC-20 mirror contract.

---

### Impact Explanation

**Impact: High — Permanent freezing of funds.**

If an `EvmErc20` or `EvmErc20V2` contract is deployed with `admin = address(0)`:

- `mint` is permanently inaccessible. Any NEAR-side deposit that triggers a bridge transfer to this token contract will succeed on the NEAR side (burning/locking the NEAR token) but will never result in minted tokens on the Aurora EVM side.
- `adminPause` is permanently inaccessible. If the contract is initialized with a non-zero `paused` flag, it can never be unpaused.
- `setMetadata` is permanently inaccessible.
- The token contract is bricked from the moment of deployment with no recovery path, since there is no `transferAdmin` or upgrade mechanism in `AdminControlled`.

Funds deposited into the bridge for this token are permanently frozen: they are locked/burned on the NEAR side but can never be claimed on the Aurora side.

---

### Likelihood Explanation

**Likelihood: Low.**

In the intended production flow, `EvmErc20`/`EvmErc20V2` contracts are deployed by the Aurora Engine itself, which sets `admin` to its own EVM address — not `address(0)`. However:

1. The missing check means there is zero on-chain protection against accidental misconfiguration during deployment.
2. A contract deployer interacting with the Aurora EVM can deploy `EvmErc20`/`EvmErc20V2` directly with `admin = address(0)`, permanently locking that instance.
3. Any future code path or upgrade that passes an uninitialized or default address would silently produce a bricked contract with no revert.

The `// slither-disable-next-line missing-zero-check` comment confirms the development team is aware of the pattern but chose suppression over remediation.

---

### Recommendation

Add a zero-address guard in the `AdminControlled` constructor:

```solidity
constructor(address _admin, uint flags) {
    require(_admin != address(0), "AdminControlled: zero admin address");
    admin = _admin;
    paused = flags;
}
``` [1](#0-0) 

Remove the `// slither-disable-next-line missing-zero-check` suppression comment once the check is in place. This fix propagates automatically to `EvmErc20` and `EvmErc20V2` since they delegate to `AdminControlled`'s constructor.

---

### Proof of Concept

1. Deploy `EvmErc20` on Aurora EVM with `admin = address(0)`:
   ```solidity
   EvmErc20 token = new EvmErc20("Test", "TST", 18, address(0));
   ```
2. Attempt to call `mint`:
   ```solidity
   token.mint(someUser, 1e18); // reverts: msg.sender != address(0)
   ```
3. The `onlyAdmin` modifier evaluates `require(msg.sender == address(0))`, which always fails for any real caller.
4. `mint` is permanently inaccessible. Any bridge deposit routed to this token contract will lock funds on the NEAR side with no corresponding mint on Aurora, permanently freezing them. [4](#0-3) [5](#0-4)

### Citations

**File:** etc/eth-contracts/contracts/AdminControlled.sol (L10-16)
```text
    constructor(address _admin, uint flags) {
        // slither-disable-next-line missing-zero-check
        admin = _admin;

        // Add the possibility to set pause flags on the initialization
        paused = flags;
    }
```

**File:** etc/eth-contracts/contracts/AdminControlled.sol (L18-21)
```text
    modifier onlyAdmin {
        require(msg.sender == admin);
        _;
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L21-24)
```text
    constructor (string memory metadata_name, string memory metadata_symbol, uint8 metadata_decimals, address admin)
        ERC20(metadata_name, metadata_symbol)
        AdminControlled(admin, 0)
    {
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L49-51)
```text
    function mint(address account, uint256 amount) public onlyAdmin {
        _mint(account, amount);
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L21-24)
```text
    constructor (string memory metadata_name, string memory metadata_symbol, uint8 metadata_decimals, address admin)
        ERC20(metadata_name, metadata_symbol)
        AdminControlled(admin, 0)
    {
```
