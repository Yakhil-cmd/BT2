[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/sui-types/src/transaction_driver_types.rs (L78-94)
```rust
impl TransactionSubmissionError {
    pub fn is_retriable(&self) -> bool {
        match self {
            Self::TransactionDriverInternalError { .. } => false,
            Self::InvalidUserSignature { .. } => false,
            Self::ObjectsDoubleUsed { .. } => false,
            Self::TimeoutBeforeFinality => true,
            Self::TimeoutBeforeFinalityWithErrors { .. } => true,
            Self::FailedWithTransientErrorAfterMaximumAttempts { .. } => true,
            Self::NonRecoverableTransactionError { .. } => false,
            Self::SystemOverload { .. } => true,
            Self::SystemOverloadRetryAfter { .. } => true,
            Self::TxAlreadyFinalizedWithDifferentUserSignatures => false,
            Self::TransactionFailed { category, .. } => category.is_submission_retriable(),
        }
    }
}
```

**File:** crates/sui-core/src/transaction_driver/error.rs (L46-64)
```rust
    pub(crate) fn categorize(&self) -> ErrorCategory {
        match self {
            TransactionRequestError::TimedOutSubmittingTransaction => ErrorCategory::Unavailable,
            TransactionRequestError::TimedOutGettingFullEffectsAtValidator => {
                ErrorCategory::Unavailable
            }
            TransactionRequestError::ValidatorInternal(_) => ErrorCategory::Internal,

            TransactionRequestError::RejectedAtValidator(error) => error.categorize(),
            TransactionRequestError::RejectedByConsensus => ErrorCategory::Aborted,
            TransactionRequestError::StatusExpired(_, _) => ErrorCategory::Aborted,
            TransactionRequestError::Aborted(error) => error.categorize(),
        }
    }

    pub(crate) fn is_submission_retriable(&self) -> bool {
        self.categorize().is_submission_retriable()
    }
}
```

**File:** crates/sui-core/src/transaction_driver/error.rs (L107-151)
```rust
impl TransactionDriverError {
    pub(crate) fn is_submission_retriable(&self) -> bool {
        self.categorize().is_submission_retriable()
    }

    pub fn categorize(&self) -> ErrorCategory {
        match self {
            TransactionDriverError::ClientInternal { .. } => ErrorCategory::Internal,
            TransactionDriverError::ValidationFailed { .. } => ErrorCategory::InvalidTransaction,
            TransactionDriverError::Aborted {
                submission_retriable_errors,
                submission_non_retriable_errors,
                ..
            } => {
                if let Some((_, _, _, category)) = submission_retriable_errors.errors.first() {
                    *category
                } else if let Some((_, _, _, category)) =
                    submission_non_retriable_errors.errors.first()
                {
                    *category
                } else {
                    ErrorCategory::Aborted
                }
            }
            TransactionDriverError::RejectedByValidators {
                submission_non_retriable_errors,
                submission_retriable_errors,
                ..
            } => {
                if let Some((_, _, _, category)) = submission_non_retriable_errors.errors.first() {
                    *category
                } else if let Some((_, _, _, category)) = submission_retriable_errors.errors.first()
                {
                    *category
                } else {
                    // There should be at least one error.
                    ErrorCategory::Internal
                }
            }
            TransactionDriverError::ForkedExecution { .. } => ErrorCategory::Internal,
            TransactionDriverError::TimeoutWithLastRetriableError { .. } => {
                ErrorCategory::Unavailable
            }
        }
    }
```

**File:** crates/sui-core/src/transaction_driver/error.rs (L279-344)
```rust
#[derive(Eq, PartialEq, Clone, Debug, Default)]
pub struct AggregatedRequestErrors {
    pub errors: Vec<(String, Vec<AuthorityName>, StakeUnit, ErrorCategory)>,
    // The total stake of all errors.
    pub total_stake: StakeUnit,
}

impl std::fmt::Display for AggregatedRequestErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = self
            .errors
            .iter()
            .map(|(error, names, stake, _category)| {
                format!(
                    "{} {{ {} }} with {} stake",
                    error,
                    names.iter().map(|n| n.concise_owned()).join(", "),
                    stake
                )
            })
            .join("; ");
        write!(f, "{}", msg)?;
        Ok(())
    }
}

// TODO(fastpath): This is a temporary fix to unify the error message between QD and TD.
// Match special handling of UserInputError in sui-json-rpc/src/error.rs NonRecoverableTransactionError
fn format_transaction_request_error(error: &TransactionRequestError) -> String {
    match error {
        TransactionRequestError::RejectedAtValidator(sui_error) => match sui_error.as_inner() {
            SuiErrorKind::UserInputError { error: user_error } => user_error.to_string(),
            _ => sui_error.to_string(),
        },
        _ => error.to_string(),
    }
}

pub(crate) fn aggregate_request_errors(
    errors: Vec<(AuthorityName, StakeUnit, TransactionRequestError)>,
) -> AggregatedRequestErrors {
    let mut total_stake = 0;
    let mut aggregated_errors =
        BTreeMap::<String, (Vec<AuthorityName>, StakeUnit, ErrorCategory)>::new();

    for (name, stake, error) in errors {
        total_stake += stake;
        let key = format_transaction_request_error(&error);
        let entry = aggregated_errors
            .entry(key)
            .or_insert_with(|| (vec![], 0, error.categorize()));
        entry.0.push(name);
        entry.1 += stake;
    }

    let mut errors: Vec<_> = aggregated_errors
        .into_iter()
        .map(|(error, (names, stake, category))| (error, names, stake, category))
        .collect();
    errors.sort_by_key(|(_, _, stake, _)| std::cmp::Reverse(*stake));

    AggregatedRequestErrors {
        errors,
        total_stake,
    }
}
```
