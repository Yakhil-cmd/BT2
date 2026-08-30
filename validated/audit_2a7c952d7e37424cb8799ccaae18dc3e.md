### Title
Vault `initialize()` is permissionless and can be front-run to grief DAO protocol launch - (File: mainnet/contracts/vault/v0-vault-stx.clar)

### Summary
Every vault's `initialize` function can be called by anyone with no authorization check, unlike every other admin function in the same contract. An attacker can call it before the DAO's bundled launch proposal does, permanently flipping the `initialized` flag and causing the DAO's atomic proposal transaction to revert, denying legitimate protocol initialization — the exact bug class described in the referenced Trader Joe finding, where a griefer permissionlessly creates the shared resource (a pool/an initialized state) ahead of the legitimate, privileged actor.

### Finding Description
Each vault contract exposes an `initialize` entrypoint guarded only by a `initialized` flag check, with **no** `check-dao-auth` call, in contrast to every other configuration function in the same contract (`set-authorized-contract`, `set-pause-states`, `set-flashloan-permissions`, etc.), which all call `(try! (check-dao-auth))`: [1](#0-0) 

```
(define-public (initialize)
  (begin
    (asserts! (not (var-get initialized)) ERR-ALREADY-INITIALIZED)
    (var-set initialized true)
    (try! (deposit MINIMUM-LIQUIDITY u0 NULL-ADDRESS))
    ...
```

compared to: [2](#0-1) 

`initialize` calls `deposit`, which pulls `MINIMUM-LIQUIDITY` (1000 units) of the underlying token from `contract-caller` — i.e. whoever calls `initialize` — and mints the resulting shares to `NULL-ADDRESS`: [3](#0-2) 

`deposit` itself requires `(asserts! (var-get initialized) ERR-INIT)`, which only becomes true because `initialize` sets it just before calling `deposit`, meaning `initialize` is the sole entrypoint for the very first deposit into an uninitialized vault, and it is open to any principal.

The DAO launches the protocol via a proposal script that bundles vault `initialize` calls together with cap-setting and market authorization, all wrapped in `try!`, and requires the deployer to pre-fund the proposal contract with the minimum-liquidity tokens before execution (mirrored by the `proposal-init-vaults.clar` pattern and `initializeVaults()` test helper, which mint/transfer `MINIMUM_LIQUIDITY` to the proposal identifier before calling `execute`): [4](#0-3) 

Because `initialize` has no access control, an unprivileged attacker can call `vault.initialize()` directly (using 1000 units of their own token balance) before the DAO's proposal executes. This sets `initialized` to `true` prematurely. When the DAO's bundled proposal later calls the same vault's `initialize`, it now hits `(asserts! (not (var-get initialized)) ERR-ALREADY-INITIALIZED)` and returns an error, causing the entire `try!`-wrapped proposal `execute` transaction to abort atomically — reverting cap-setting, market authorization, and any other steps bundled with it.

This mirrors the referenced finding precisely: `JoeFactory.createPair` was permissionless and could be front-run by a griefer to block `LaunchEvent.createPair`, forcing an emergency unwind. Here, the vault's shared `initialized` boolean is the equivalent "shared resource" that an unprivileged attacker (the griefer) primes ahead of the privileged, legitimate initializer (the DAO executor), causing the legitimate multi-step transaction to fail.

### Impact Explanation
- **Victim**: the DAO/deployer and, transitively, all future depositors/borrowers who cannot use the market until it is correctly initialized.
- **Attacker**: any unprivileged address, at the cost of only `MINIMUM_LIQUIDITY` (1000 units) of the underlying token, which is burned to `NULL-ADDRESS` with no recovery path.
- Without the attacker's transaction: the DAO's bundled proposal executes atomically, initializing the vault, setting caps, and authorizing the market — the protocol launches as intended.
- With the attacker's transaction: the DAO's proposal reverts on the `initialize` call inside the `try!` chain. Any tokens the deployer/DAO pre-transferred to the proposal contract for this step remain stranded there (proposal contracts are typically single-use/immutable with no withdrawal function), and the vault/market cannot be brought online through the intended path, freezing deployment and any pre-committed launch funds.
- This lands on **temporary freezing of funds** (the pre-funded minimum-liquidity tokens and the inability to bring the market online until the DAO redeploys/adjusts the proposal), which is one of the in-scope High impact classes.

### Likelihood Explanation
Likelihood is moderate: this only matters during protocol deployment/vault (re)launch windows, is publicly observable (proposal transactions/pending initialization are visible on-chain before confirmation), and the attack cost is small and fixed (1000 units of the underlying token, potentially just the STX-pegged token, or a stablecoin — cheap relative to the disruption caused). No special privileges are required by the attacker.

### Recommendation
Restrict `initialize` to the DAO by adding `(try! (check-dao-auth))` at the top of the function, consistent with every other privileged setup function (`set-authorized-contract`, `set-pause-states`, `set-flashloan-permissions`) in the same contract. Alternatively, have the DAO proposal check `(var-get initialized)` before attempting to call `initialize`, and treat "already initialized" as a non-fatal, skippable step rather than aborting the entire atomic proposal.

### Proof of Concept
1. Deployer prepares the protocol-launch DAO proposal (e.g., analogous to `proposal-init-vaults.clar`) and transfers `MINIMUM_LIQUIDITY` (1000) units of, e.g., sBTC to the proposal contract's principal, intending for the proposal's `execute` to call `vault-sbtc.initialize()`.
2. Before the DAO executes the proposal, an attacker (any address holding 1000 units of sBTC) calls `vault-sbtc.initialize()` directly. There is no auth check, so this succeeds: [1](#0-0) 
   `initialized` becomes `true`, and 1000 units of the attacker's sBTC are deposited/burned to `NULL-ADDRESS`.
3. The DAO executor now runs the bundled proposal's `execute`, which includes `(try! (contract-call? .vault-sbtc initialize))` (or the wired equivalent). This call now hits `ERR-ALREADY-INITIALIZED` and returns an error.
4. Because the call is wrapped in `try!` inside the proposal's atomic `execute`, the entire proposal transaction reverts — cap-setting, market authorization, and any other steps in the same proposal never take effect, and the deployer's pre-transferred minimum-liquidity tokens sent to the (typically non-recoverable) proposal contract remain stranded.

### Citations

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L492-507)
```text
(define-public (initialize)
  (begin
    (asserts! (not (var-get initialized)) ERR-ALREADY-INITIALIZED)
    (var-set initialized true)
    (try! (deposit MINIMUM-LIQUIDITY u0 NULL-ADDRESS))
    
    (print {
      action: "vault-initialize",
      caller: contract-caller,
      data: {
        vault: UNDERLYING,
        minimum-liquidity: MINIMUM-LIQUIDITY
      }
    })
    
    (ok true)))
```

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L511-513)
```text
(define-public (set-authorized-contract (contract principal) (authorized bool))
  (begin
    (try! (check-dao-auth))
```

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L761-782)
```text
(define-public (deposit (amount uint) (min-out uint) (recipient principal))
    (let (
      (states (var-get pause-states))
      (u (try! (accrue)))
      (account contract-caller)
      (CAP-SUPPLY (var-get cap-supply))
      (current-assets (var-get assets))
      (inkind (convert-to-shares-preview amount)))

    (asserts! (not (get deposit states)) ERR-PAUSED)
    (asserts! (var-get initialized) ERR-INIT)
    (asserts! (not (var-get in-flashloan)) ERR-REENTRANCY)
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)
    (asserts! (>= inkind min-out) ERR-SLIPPAGE)
    (asserts! (<= (+ current-assets amount) CAP-SUPPLY) ERR-SUPPLY-CAP-EXCEEDED)

    (try! (receive-underlying amount account))
    (try! (ft-mint? zft inkind recipient))
    (var-set assets (+ current-assets amount))

    (print {
      action: "deposit",
```

**File:** local-testing/tests/setup/helpers.ts (L198-212)
```typescript
// Initialize vaults and set authorization via DAO proposal
export function initializeVaults() {
  // Mint tokens to dao-executor for vault initialization (minimum liquidity = 1000)
  const MINIMUM_LIQUIDITY = 1000n;
  txOk(sbtcToken.mint(MINIMUM_LIQUIDITY, proposalInitVaults.identifier), deployer);
  txOk(usdhToken.mint(MINIMUM_LIQUIDITY, proposalInitVaults.identifier), deployer);
  txOk(contracts.usdc.mint(MINIMUM_LIQUIDITY, proposalInitVaults.identifier), deployer);
  txOk(contracts.ststx.mint(MINIMUM_LIQUIDITY, proposalInitVaults.identifier), deployer);
  
  // wSTX cannot be minted, so we transfer it from deployer to dao-executor
  // Deployer should have enough STX balance from simnet setup
  txOk(wstxToken.transfer(MINIMUM_LIQUIDITY, deployer, proposalInitVaults.identifier, null), deployer);
  
  // Execute proposal to initialize vaults and set authorization
  executeDaoProposal(proposalInitVaults, deployer);
```
