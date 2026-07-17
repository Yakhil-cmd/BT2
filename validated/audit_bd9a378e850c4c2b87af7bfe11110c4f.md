I'll analyze the bug class from the external report and search for a nearcore-native analog. The core issue is: a stored/accumulated value is compared against a recalculated value using parameters that can decrease, causing an assertion to fail and blocking user operations.

Let me search for relevant patterns in nearcore's production code.