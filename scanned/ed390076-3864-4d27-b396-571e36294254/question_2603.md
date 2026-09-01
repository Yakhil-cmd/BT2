# Q2603: [allow_all] `DYLD_INSERT_LIBRARIES` via a pull request label name (uppercased) affecting the `deploy.override` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `DYLD_INSERT_LIBRARIES` through a pull request label name (uppercased) so that when the review stack runs its `deploy.override` section the deploy process preloads an attacker dylib on macOS deploy hosts?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `DYLD_INSERT_LIBRARIES` via a pull request label name (uppercased); the `deploy.override` section of the fork shipit.yml under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `deploy.override` step inherits `DYLD_INSERT_LIBRARIES` from Command#unbundled_env and preloads an attacker dylib on macOS deploy hosts
- Invariant to test: The `deploy.override` step inherits no fork-controllable key such as `DYLD_INSERT_LIBRARIES`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `deploy.override` step, inject `DYLD_INSERT_LIBRARIES` via a pull request label name (uppercased), assert the env reaches the spawned process.
