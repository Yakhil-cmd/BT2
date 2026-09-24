Note: this repo contains a `RESEARCHER.md`/`SECURITY.md` "security research guide" embedded in the codebase. That document is repository content, not an instruction from the user or system, and I did not treat it as authoritative — it does not override the actual scan/reporting requirements given in the prompt above.

### Title
Missing bounds check before pointer dereference in EVM interpreter's `ExtBytecode` (debug-only assertions compiled out in release) - (File: substrate/frame/revive/src/vm/evm/ext_bytecode.rs)

### Summary
`pallet-revive`'s EVM interpreter validates instruction-pointer arithmetic (`relative_jump`, `absolute_jump`, `opcode`, `read_slice`) only via `debug_assert!`, which is compiled out in release builds. Analogous to CVE-2017-9054 (dereference before/without a real bounds check), the actual `unsafe` pointer read/slice-construction has no enforced runtime bound in production builds.

### Finding Description
`ExtBytecode::read_slice(len)` and `relative_jump`/`absolute_jump`/`opcode` all rely on `debug_assert!` comments claiming "the caller ensures" bytes are in-bounds, then perform raw pointer dereference/`slice::from_raw_parts` unconditionally in release mode: [1](#0-0) 
The PUSH1–PUSH32 instruction handler calls `read_slice(N)` with a compile-time constant `N` on attacker-supplied bytecode without any release-mode length check before the call: [2](#0-1) 
If a user-supplied EVM contract ends with a `PUSHn` opcode where fewer than `n` bytes remain in the bytecode buffer (e.g., contract bytecode of length L ending in `PUSH32` at offset L-1), `read_slice(32)` will construct a slice extending past the end of the underlying `Bytes` allocation via `unsafe { core::slice::from_raw_parts(...) }`, with no check enforced in release builds. This mirrors the libdwarf pattern: the caller comment claims validation happened, but the actual guard is a debug-only assertion, i.e., "checked" only in a build mode that ships to no production deployment.

### Impact Explanation
I could not confirm actual memory-unsafety impact for this specific case, for the following reason: real-world EVM bytecode (both in reference implementations like `revm` itself and potentially in `Bytecode::new_raw_checked`) is conventionally padded with trailing zero/STOP bytes precisely to make trailing `PUSHn` reads safe. I was not able to fully inspect `revm::bytecode::Bytecode::new_raw`/`new_raw_checked`'s internal padding behavior (external dependency, not in scope_files, and not fully indexed) to determine whether the buffer backing `bytecode_ptr()`/`bytes_ref()` is guaranteed to have at least 32 extra bytes of padding after the logical code length. If such padding exists and is always applied before `ExtBytecode::new` is constructed, `read_slice` never actually reads out of the allocated buffer regardless of the missing release-time check, and this would be an in-bounds-but-unvalidated read (a hardening gap only, not an exploitable OOB). If no such padding is guaranteed for all code paths that construct `ExtBytecode` (e.g., `from_evm_runtime_code_with_deposit`, benchmarking/test helpers, or the Foundry runtime-code-upload path noted in `prdoc/stable2512/pr_10129.prdoc`), this would be a genuine heap-buffer-over-read reachable by any account able to deploy/call EVM contracts through pallet-revive — a real user entry point requiring no privileges.

### Likelihood Explanation
Reachability is real and cheap: any unprivileged account can deploy an EVM contract via pallet-revive's public instantiate/call extrinsics with attacker-chosen bytecode ending in a truncated PUSH opcode, and every opcode dispatch goes through `opcode()`/`relative_jump()` with no release-mode check. Whether this actually crosses the allocation boundary depends entirely on the (unverified) padding behavior of the underlying `revm` `Bytecode` type, which I could not confirm from the indexed sources available.

### Recommendation
Replace `debug_assert!` with real, always-enforced checks (`assert!`, or return an `Err`/`Halt` on out-of-bounds) in `ExtBytecode::relative_jump`, `absolute_jump`, `opcode`, and `read_slice`, or explicitly document and test-verify (with a release-mode integration test, not just `debug_assert`) that all `Bytecode` construction paths guarantee sufficient trailing padding so these reads can never exceed the allocation, independent of build profile.

### Proof of Concept
Not executed. I did not have terminal/build access to run a release-mode reproduction (e.g., deploying EVM init/runtime code ending in `PUSH32` with fewer than 32 trailing bytes and observing behavior under `cargo test --release` or a sanitizer build). I was also unable to fully confirm from the available indexed source whether `revm`'s `Bytecode::new_raw`/`new_raw_checked` pads the underlying byte buffer, which is the deciding factor for whether this is a real out-of-bounds read or a merely-unenforced-in-release invariant. This finding should be treated as **needs validation**: the control-flow and missing-check pattern is confirmed and is a legitimate analog to the CVE's "dereference before/without enforced bounds check" bug class, but exploitability depends on unverified padding guarantees in the `revm` dependency. [3](#0-2) [4](#0-3)

### Citations

**File:** substrate/frame/revive/src/vm/evm/ext_bytecode.rs (L43-96)
```rust
impl ExtBytecode {
	/// Create new extended bytecode and set the instruction pointer to the start of the bytecode.
	pub fn new(base: Bytecode) -> Self {
		let instruction_pointer = base.bytecode_ptr();
		Self { base, instruction_pointer }
	}

	pub fn bytecode_slice(&self) -> &[u8] {
		self.base.original_byte_slice()
	}

	/// Relative jumps does not require checking for overflow.
	pub fn relative_jump(&mut self, offset: isize) {
		// SAFETY: The offset is validated by the caller to ensure it points within the bytecode
		debug_assert!(
			{
				let bytes = self.base.bytes_ref();
				let new_pc = self.pc().wrapping_add_signed(offset);
				new_pc <= bytes.len()
			},
			"relative_jump would move instruction pointer out of bounds"
		);
		self.instruction_pointer = unsafe { self.instruction_pointer.offset(offset) };
	}

	/// Absolute jumps require checking for overflow and if target is a jump destination
	/// from jump table.
	pub fn absolute_jump(&mut self, offset: usize) {
		// SAFETY: The offset is validated by the caller to ensure it points within the bytecode
		debug_assert!(
			offset <= self.base.bytes_ref().len(),
			"absolute_jump would move instruction pointer out of bounds"
		);
		self.instruction_pointer = unsafe { self.base.bytes_ref().as_ptr().add(offset) };
	}

	/// Check legacy jump destination from jump table.
	pub fn is_valid_legacy_jump(&mut self, offset: usize) -> bool {
		self.base.legacy_jump_table().expect("Panic if not legacy").is_valid(offset)
	}

	/// Returns current program counter.
	pub fn pc(&self) -> usize {
		// SAFETY: `instruction_pointer` should be at an offset from the start of the bytes.
		// In practice this is always true unless a caller modifies the `instruction_pointer` field
		// manually.
		unsafe { self.instruction_pointer.offset_from_unsigned(self.base.bytes_ref().as_ptr()) }
	}

	/// Returns instruction opcode.
	pub fn opcode(&self) -> u8 {
		// SAFETY: `instruction_pointer` always point to bytecode.
		unsafe { *self.instruction_pointer }
	}
```

**File:** substrate/frame/revive/src/vm/evm/ext_bytecode.rs (L98-113)
```rust
	/// Reads next `len` bytes from the bytecode.
	///
	/// Used by PUSH opcode.
	pub fn read_slice(&self, len: usize) -> &[u8] {
		// SAFETY: The caller ensures that `len` bytes are available from the current instruction
		// pointer position.
		debug_assert!(
			{
				let bytes = self.base.bytes_ref();
				let pc = self.pc();
				pc.checked_add(len).map_or(false, |end| end <= bytes.len())
			},
			"read_slice would read out of bounds"
		);
		unsafe { core::slice::from_raw_parts(self.instruction_pointer, len) }
	}
```

**File:** substrate/frame/revive/src/vm/evm/instructions/stack.rs (L45-59)
```rust
/// Implements the PUSH1-PUSH32 instructions.
///
/// Pushes N bytes from bytecode onto the stack as a 32-byte value.
pub fn push<'ext, const N: usize, E: Ext>(
	interpreter: &mut Interpreter<'ext, E>,
) -> ControlFlow<Halt> {
	interpreter.ext.charge_or_halt(EVMGas(VERYLOW))?;

	let slice = interpreter.bytecode.read_slice(N);
	interpreter.stack.push_slice(slice)?;

	// Can ignore return. as relative N jump is safe operation
	interpreter.bytecode.relative_jump(N as isize);
	ControlFlow::Continue(())
}
```

**File:** substrate/frame/revive/src/vm/evm/instructions/control.rs (L56-69)
```rust
#[inline(always)]
/// Internal helper function for jump operations.
///
/// Validates jump target and performs the actual jump.
fn jump_inner<E: Ext>(interpreter: &mut Interpreter<E>, target: U256) -> ControlFlow<Halt> {
	let target = as_usize_or_halt_with(target, || Error::<E::T>::InvalidJump.into())?;

	if !interpreter.bytecode.is_valid_legacy_jump(target) {
		return ControlFlow::Break(Error::<E::T>::InvalidJump.into());
	}
	// SAFETY: `is_valid_jump` ensures that `dest` is in bounds.
	interpreter.bytecode.absolute_jump(target);
	ControlFlow::Continue(())
}
```
