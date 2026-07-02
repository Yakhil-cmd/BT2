Let me trace the exact code path described in this question.

Let me check the error classification to confirm whether `NewTransactionFeeDeductionFailedError` is a `CodedError` vs `CodedFailure`, and look at the `IsFailure` check.