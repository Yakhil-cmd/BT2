Looking at the codebase, I need to trace the bootstrap declare path through gateway admission, blockifier execution, and the OS Cairo code to determine if there's a valid analog.

Let me check the `check_declare_permissions` and `enforce_fee` implementations to complete the picture.