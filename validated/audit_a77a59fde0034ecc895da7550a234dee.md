Let me analyze the bug class from the external report and search for a nearcore-native analog. The core pattern is: a mutable global variable set at initialization is used to process historical records, but an admin function can change it, causing the historical records to be processed with the wrong value.

Let me search for similar patterns in nearcore's production code.