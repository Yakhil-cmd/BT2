# Q0424: [allow_with_label] `DYLD_INSERT_LIBRARIES` via a pull request label name (uppercased) affecting the `fetch` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `DYLD_INSERT_LIBRARIES` through a pull request label name (uppercased) so that when the review stack runs its `fetch` section the deploy process preloads an attacker dylib on macOS deploy hosts?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `DYLD_INSERT_LIBRARIES` via a pull request label name (uppercased); the `fetch` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `fetch` step inherits `DYLD_INSERT_LIBRARIES` from Command#unbundled_env and preloads an attacker dylib on macOS deploy hosts
- Invariant to test: The `fetch` step inherits no fork-controllable key such as `DYLD_INSERT_LIBRARIES`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `fetch` step, inject `DYLD_INSERT_LIBRARIES` via a pull request label name (uppercased), assert the env reaches the spawned process.
