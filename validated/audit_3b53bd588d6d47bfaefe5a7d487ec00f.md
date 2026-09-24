No vulnerability found for this question.

**Rationale:** The reported bug class is a classic SQL injection via string concatenation of an authenticated web-app parameter (`id_memorando`) into a raw SQL query in an unrelated PHP application (WeGIA). The Polkadot SDK's only SQL usage is in the off-chain `eth-rpc` receipt indexer [1](#0-0) , which is not part of consensus-critical runtime code and is not reachable via a signed extrinsic, permitted contract call, or XCM message as required by the analog criteria.

All queries in that file bind parameters through `sqlx::query!` compile-time-checked macros or `QueryBuilder::push_bind`, never interpolating attacker-controlled values directly into SQL text [2](#0-1) [3](#0-2) . The only places using `format!` to build SQL strings only substitute a fixed number of `"?"` placeholders or hardcoded table names, never raw user data [4](#0-3) , so no string-concatenation injection vector exists.

Since there is no attacker-reachable entry point (no signed extrinsic, contract call, or XCM message feeds this component) and no unparameterized query construction exists, there is no demonstrable Polkadot SDK analog to the WeGIA CVE-2026-23723 SQL injection.

### Citations

**File:** substrate/frame/revive/rpc/src/receipt_provider.rs (L17-35)
```rust
use crate::{
	Address, BlockInfoProvider, BlockNumberOrTag, Bytes, ChainMetadata, ClientError, Filter,
	FilterBlockOption, Log, ReceiptExtractor, ReceiptInfo, SubxtBlockInfoProvider, SyncLabel,
	SyncStateKey,
	block_sync::SyncCheckpoint,
	client::{SubstrateBlock, SubstrateBlockNumber},
};
use futures::future::OptionFuture;
use pallet_revive::evm::TransactionSigned;
use sp_core::{H256, U256};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool, query};
use std::{
	collections::{BTreeMap, HashMap},
	sync::Arc,
};
use tokio::sync::Mutex;

const LOG_TARGET: &str = "eth-rpc::receipt_provider";
const MAX_LOG_RESULTS: usize = 10_000;
```

**File:** substrate/frame/revive/rpc/src/receipt_provider.rs (L292-300)
```rust
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
