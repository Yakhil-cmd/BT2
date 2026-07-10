Looking at the external report's vulnerability class — an off-by-one comparison operator bug (`<` vs `<=`) in a boundary check that causes incorrect behavior when values are equal — I need to find an analogous issue in the threshold-signatures codebase.

Let me examine the threshold validation logic across the codebase.