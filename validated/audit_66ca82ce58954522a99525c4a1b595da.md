No vulnerability found for this question.

The original report describes a pure front-running attack (transaction-ordering race to register/claim a deployed contract address before its rightful deployer). The scan methodology explicitly requires rejecting "pure front-running/economic attacks" as a bug class (see rejection criteria in the prompt). 

I looked for genuine Polkadot SDK analogs involving deterministic address derivation and contract registration — e.g., `pallet-revive`'s `create1`/`create2` address derivation [1](#0-0)  and `pallet-contracts`'s `DefaultAddressGenerator` [2](#0-1) , both of which make contract addresses predictable before deployment (analogous to Alice deploying a strategy contract with a known/predictable address). However, any exploitation of this predictability to "steal" a deployment slot is inherently a front-running/transaction-ordering attack — the same excluded bug class as the source report — and does not by itself demonstrate a distinct checks/mutation/loss chain that survives the methodology's exclusion criteria.

I also found a related but structurally different, already-documented behavior: `pallet-contracts`'s `InstantiateOrigin` permission is not enforced when a contract instantiates another contract [3](#0-2)  and the corresponding PRDoc `prdoc/1.9.0/pr_3377.prdoc` [4](#0-3) . This is a documented, intentional design limitation (not a front-running race) and does not match the invariant violated in the source report, so it does not qualify as the requested analog either.

No demonstrable, non-front-running Polkadot SDK analog with a concrete attacker-controlled entry point, violated check, and measurable loss was found.

### Citations

**File:** substrate/frame/revive/src/address.rs (L263-285)
```rust
/// Determine the address of a contract using CREATE semantics.
pub fn create1(deployer: &H160, nonce: u64) -> H160 {
	let mut list = rlp::RlpStream::new_list(2);
	list.append(&deployer.as_bytes());
	list.append(&nonce);
	let hash = keccak_256(&list.out());
	H160::from_slice(&hash[12..])
}

/// Determine the address of a contract using the CREATE2 semantics.
pub fn create2(deployer: &H160, code: &[u8], input_data: &[u8], salt: &[u8; 32]) -> H160 {
	let init_code_hash = {
		let init_code: Vec<u8> = code.into_iter().chain(input_data).cloned().collect();
		keccak_256(init_code.as_ref())
	};
	let mut bytes = [0; 85];
	bytes[0] = 0xff;
	bytes[1..21].copy_from_slice(deployer.as_bytes());
	bytes[21..53].copy_from_slice(salt);
	bytes[53..85].copy_from_slice(&init_code_hash);
	let hash = keccak_256(&bytes);
	H160::from_slice(&hash[12..])
}
```

**File:** substrate/frame/contracts/src/address.rs (L45-67)
```rust
/// Default address generator.
///
/// This is the default address generator used by contract instantiation. Its result
/// is only dependent on its inputs. It can therefore be used to reliably predict the
/// address of a contract. This is akin to the formula of eth's CREATE2 opcode. There
/// is no CREATE equivalent because CREATE2 is strictly more powerful.
/// Formula:
/// `hash("contract_addr_v1" ++ deploying_address ++ code_hash ++ input_data ++ salt)`
pub struct DefaultAddressGenerator;

impl<T: Config> AddressGenerator<T> for DefaultAddressGenerator {
	/// Formula: `hash("contract_addr_v1" ++ deploying_address ++ code_hash ++ input_data ++ salt)`
	fn contract_address(
		deploying_address: &T::AccountId,
		code_hash: &CodeHash<T>,
		input_data: &[u8],
		salt: &[u8],
	) -> T::AccountId {
		let entropy = (b"contract_addr_v1", deploying_address, code_hash, input_data, salt)
			.using_encoded(T::Hashing::hash);
		Decode::decode(&mut TrailingZeroInput::new(entropy.as_ref()))
			.expect("infinite length input; no invalid inputs for type; qed")
	}
```

**File:** substrate/frame/contracts/src/lib.rs (L426-435)
```rust
		/// Origin allowed to instantiate code.
		///
		/// # Note
		///
		/// This is not enforced when a contract instantiates another contract. The
		/// [`Self::UploadOrigin`] should make sure that no code is deployed that does unwanted
		/// instantiations.
		///
		/// By default, it is safe to set this to `EnsureSigned`, allowing anyone to instantiate
		/// contract code.
```

**File:** prdoc/1.9.0/pr_3377.prdoc (L1-14)
```text
# Schema: Polkadot SDK PRDoc Schema (prdoc) v1.0.0
# See doc at https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/prdoc/schema_user.json

title: Permissioned contract deployment

doc:
  - audience: Runtime Dev
    description: |
      This PR introduces two new config types that specify the origins allowed to
      upload and instantiate contract code. However, this check is not enforced when
      a contract instantiates another contract.

crates: 
- name: pallet-contracts
```
