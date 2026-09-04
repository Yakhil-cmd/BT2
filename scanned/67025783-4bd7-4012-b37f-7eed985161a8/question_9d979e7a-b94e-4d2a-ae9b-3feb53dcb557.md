);
                op_error::InvalidInput
            })?
            .as_ref()
            .ok_or_else(|| {
                warn!(
