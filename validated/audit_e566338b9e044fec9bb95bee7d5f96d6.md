No vulnerability found for this question.

The only SQL usage in this repository is in the off-chain `eth-rpc` proxy's SQLite receipt store, and it uses parameterized queries consistently. The `find_transaction`, `get_substrate_hash`, `get_ethereum_hash`, `get_sync_label`, `set_sync_label`, `delete_sync_label`, `receipts_count_per_block`, and `block_transaction_hashes` functions all bind values via `sqlx::query!` macros with `$1`/`$2` placeholders rather than string concatenation. [1](#0-0) [2](#0-1) 

The dynamic-query paths in `logs()` and `logs_by_block_number()` build queries with `QueryBuilder` and always use `push_bind` for values (block numbers, hashes, addresses, topics), never interpolating raw attacker input into SQL text. [3](#0-2) 

The only `format!`-constructed SQL is in `remove()`, where the interpolated content is just a fixed count of `"?"` placeholders (not attacker data) and hardcoded table names, with actual values bound afterward via `.bind()`. [4](#0-3)  The topic index in `format_args!(" AND topic_{i} IN (")` is a bounded loop index (0–3) into fixed array positions, not attacker-controlled string content. [5](#0-4) 

Beyond this, `sql` matches in this repo are limited to a migration file, RPC client CLI options, and dependency declarations — none of which construct queries from unsanitized user input. [6](#0-5) 

Additionally, this component is an off-chain JSON-RPC indexing service, not a signed extrinsic, contract call, or XCM entry point processed by consensus-critical FRAME runtime logic, so it does not meet the report's required "real user entry" criteria even if a flaw existed here.

### Citations

**File:** substrate/frame/revive/rpc/src/receipt_provider.rs (L290-300)
```rust
	pub async fn find_transaction(&self, transaction_hash: &H256) -> Option<(H256, usize)> {
		let transaction_hash_bytes = transaction_hash.as_ref();
		let result = query!(
			r#"
			SELECT block_hash, transaction_index
			FROM transaction_hashes
			WHERE transaction_hash = $1
			"#,
			transaction_hash_bytes
		)
		.fetch_optional(&self.db_ctx.pool)
```

**File:** substrate/frame/revive/rpc/src/receipt_provider.rs (L381-399)
```rust
		for chunk in block_mappings.chunks(self.db_ctx.max_variable_number) {
			let placeholders = vec!["?"; chunk.len()].join(", ");
			let sql_tx =
				format!("DELETE FROM transaction_hashes WHERE block_hash in ({placeholders})");
			let sql_logs = format!("DELETE FROM logs WHERE block_hash in ({placeholders})");
			let sql_mappings = format!(
				"DELETE FROM eth_to_substrate_blocks WHERE substrate_block_hash in ({placeholders})"
			);

			let mut delete_tx_query = sqlx::query(&sql_tx);
			let mut delete_logs_query = sqlx::query(&sql_logs);
			let mut delete_mappings_query = sqlx::query(&sql_mappings);

			for block_map in chunk {
				delete_tx_query = delete_tx_query.bind(block_map.substrate_hash.as_ref());
				delete_logs_query = delete_logs_query.bind(block_map.ethereum_hash.as_ref());
				delete_mappings_query =
					delete_mappings_query.bind(block_map.substrate_hash.as_ref());
			}
```

**File:** substrate/frame/revive/rpc/src/receipt_provider.rs (L411-424)
```rust
	pub async fn get_sync_label(
		&self,
		label: impl SyncStateKey,
	) -> Result<Option<SyncCheckpoint>, ClientError> {
		let label_str = label.to_string();
		let row = query!(
			r#"
			SELECT block_number, block_hash
			FROM sync_state
			WHERE label = $1
			"#,
			label_str
		)
		.fetch_optional(&self.db_ctx.pool)
```

**File:** substrate/frame/revive/rpc/src/receipt_provider.rs (L731-798)
```rust
		let mut qb = QueryBuilder::<Sqlite>::new("SELECT logs.* FROM logs WHERE 1=1");
		let filter = filter.unwrap_or_default();

		match filter.block_option {
			FilterBlockOption::AtBlockHash(hash) => {
				qb.push(" AND block_hash = ").push_bind(hash.as_slice().to_vec());
			},
			FilterBlockOption::Range { from_block, to_block } => {
				let from_block =
					OptionFuture::from(from_block.map(&resolve_block_number)).await.transpose()?;
				let to_block =
					OptionFuture::from(to_block.map(&resolve_block_number)).await.transpose()?;

				// Read the latest block *after* resolving the tags.
				let latest_block = U256::from(self.block_provider.latest_block_number().await);

				match (from_block, to_block) {
					(Some(block), _) | (_, Some(block)) if block > latest_block => {
						anyhow::bail!("block number exceeds latest block");
					},
					(Some(from_block), Some(to_block)) if from_block > to_block => {
						anyhow::bail!("invalid block range params");
					},
					(Some(from_block), Some(to_block)) if from_block == to_block => {
						qb.push(" AND block_number = ").push_bind(from_block.as_u64() as i64);
					},
					(Some(from_block), Some(to_block)) => {
						qb.push(" AND block_number BETWEEN ")
							.push_bind(from_block.as_u64() as i64)
							.push(" AND ")
							.push_bind(to_block.as_u64() as i64);
					},
					(Some(from_block), None) => {
						qb.push(" AND block_number >= ").push_bind(from_block.as_u64() as i64);
					},
					(None, Some(to_block)) => {
						qb.push(" AND block_number <= ").push_bind(to_block.as_u64() as i64);
					},
					(None, None) => {
						qb.push(" AND block_number = ").push_bind(latest_block.as_u64() as i64);
					},
				}
			},
		}

		if !filter.address.is_empty() {
			qb.push(" AND address IN (");
			let mut separated = qb.separated(", ");
			for addr in filter.address {
				separated.push_bind(addr.as_slice().to_vec());
			}
			separated.push_unseparated(")");
		}

		for (i, topic) in filter.topics.into_iter().enumerate() {
			if topic.is_empty() {
				continue;
			}

			qb.push(format_args!(" AND topic_{i} IN ("));
			let mut separated = qb.separated(", ");
			for hash in topic {
				separated.push_bind(hash.as_slice().to_vec());
			}
			separated.push_unseparated(")");
		}

		qb.push(" LIMIT ").push_bind(MAX_LOG_RESULTS as i64);
```

**File:** substrate/frame/revive/rpc/migrations/0001_create_transaction_hashes.sql (L1-4)
```sql
-- Useful commands:
--
-- Set DATABASE_URL environment variable.
-- export DATABASE_URL=sqlite:///$HOME/eth_rpc.db
```
