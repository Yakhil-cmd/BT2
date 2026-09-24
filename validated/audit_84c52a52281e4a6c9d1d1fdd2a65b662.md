No vulnerability found for this question.

The GeoServer/GeoWebCache advisory concerns an unauthenticated HTTP home page unintentionally leaking version, build revision, config file paths, and storage locations with no opt-out check. Searching the Polkadot SDK for an analogous "unintended disclosure via unauthenticated entry point" pattern instead turns up only intentionally documented, public JSON-RPC methods designed explicitly to report this information: `system_name`, `system_version`, `system_chain`, `system_properties`, `system_localPeerId`, `system_localListenAddresses`, and the explicitly-labeled-unstable `system_unstable_networkState` [1](#0-0) . These are purposeful, documented API surface (not a bypassed/missing check) — the `SystemInfo` struct exposing `impl_name`/`impl_version`/`chain_name` is intentionally constructed and served [2](#0-1) , and node version/role/database path are deliberately logged/printed by `print_node_infos` for operator visibility [3](#0-2) .

Unlike the GeoServer case — a web page with **no check at all** to gate sensitive info from any anonymous visitor — Substrate's equivalents are: (1) intentional, versioned, documented RPC methods rather than an accidental omission of an access check; (2) gated behind node-operator RPC exposure configuration (`--rpc-external`, `--unsafe-rpc-external`, method safety filters via `DenyUnsafe`) rather than a public unauthenticated web endpoint by default; and (3) not reachable via any signed extrinsic, XCM message, or contract call — they are client/node-level JSON-RPC surface, outside the "real user entry" boundaries required by this analysis (signed extrinsic, contract call, XCM execute/send, or proof submission). There is no FRAME pallet, XCM executor, or bridge component that inadvertently discloses version/revision metadata through a missing authorization check reachable by an unprivileged on-chain actor.

Since the underlying bug class here is a web-application/HTTP endpoint missing an access-control check for build/version metadata, and no comparable unauthenticated, un-gated disclosure exists in the Polkadot SDK's runtime/extrinsic/XCM/bridge attack surface, no valid analog applies to this report.

### Citations

**File:** substrate/client/rpc-api/src/system/mod.rs (L30-82)
```rust
#[rpc(client, server)]
pub trait SystemApi<Hash, Number> {
	/// Get the node's implementation name. Plain old string.
	#[method(name = "system_name")]
	fn system_name(&self) -> Result<String, Error>;

	/// Get the node implementation's version. Should be a semver string.
	#[method(name = "system_version")]
	fn system_version(&self) -> Result<String, Error>;

	/// Get the chain's name. Given as a string identifier.
	#[method(name = "system_chain")]
	fn system_chain(&self) -> Result<String, Error>;

	/// Get the chain's type.
	#[method(name = "system_chainType")]
	fn system_type(&self) -> Result<sc_chain_spec::ChainType, Error>;

	/// Get a custom set of properties as a JSON object, defined in the chain spec.
	#[method(name = "system_properties")]
	fn system_properties(&self) -> Result<sc_chain_spec::Properties, Error>;

	/// Return health status of the node.
	///
	/// Node is considered healthy if it is:
	/// - connected to some peers (unless running in dev mode)
	/// - not performing a major sync
	#[method(name = "system_health")]
	async fn system_health(&self) -> Result<Health, Error>;

	/// Returns the base58-encoded PeerId of the node.
	#[method(name = "system_localPeerId")]
	async fn system_local_peer_id(&self) -> Result<String, Error>;

	/// Returns the multi-addresses that the local node is listening on
	///
	/// The addresses include a trailing `/p2p/` with the local PeerId, and are thus suitable to
	/// be passed to `addReservedPeer` or as a bootnode address for example.
	#[method(name = "system_localListenAddresses")]
	async fn system_local_listen_addresses(&self) -> Result<Vec<String>, Error>;

	/// Returns currently connected peers
	#[method(name = "system_peers", with_extensions)]
	async fn system_peers(&self) -> Result<Vec<PeerInfo<Hash, Number>>, Error>;

	/// Returns current state of the network.
	///
	/// **Warning**: This API is not stable. Please do not programmatically interpret its output,
	/// as its format might change at any time.
	// TODO: the future of this call is uncertain: https://github.com/paritytech/substrate/issues/1890
	// https://github.com/paritytech/substrate/issues/5541
	#[method(name = "system_unstable_networkState", with_extensions)]
	async fn system_network_state(&self) -> Result<JsonValue, Error>;
```

**File:** substrate/client/rpc-api/src/system/helpers.rs (L25-38)
```rust
/// Running node's static details.
#[derive(Clone, Debug)]
pub struct SystemInfo {
	/// Implementation name.
	pub impl_name: String,
	/// Implementation version.
	pub impl_version: String,
	/// Chain name.
	pub chain_name: String,
	/// A custom set of properties defined in the chain spec.
	pub properties: Properties,
	/// The type of this chain.
	pub chain_type: ChainType,
}
```

**File:** substrate/client/cli/src/runner.rs (L174-190)
```rust
/// Log information about the node itself.
pub fn print_node_infos<C: SubstrateCli>(config: &Configuration) {
	info!("{}", C::impl_name());
	info!("✌️  version {}", C::impl_version());
	info!("❤️  by {}, {}-{}", C::author(), C::copyright_start_year(), Local::now().year());
	info!("📋 Chain specification: {}", config.chain_spec.name());
	info!("🏷  Node name: {}", config.network.node_name);
	info!("👤 Role: {}", config.display_role());
	info!(
		"💾 Database: {} at {}",
		config.database,
		config
			.database
			.path()
			.map_or_else(|| "<unknown>".to_owned(), |p| p.display().to_string())
	);
}
```
