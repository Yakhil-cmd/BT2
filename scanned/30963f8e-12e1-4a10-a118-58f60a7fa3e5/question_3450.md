# Q3450: [allow_with_label] `LD_PRELOAD` via a pull request label name (uppercased) affecting the `review.checklist` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `LD_PRELOAD` through a pull request label name (uppercased) so that when the review stack runs its `review.checklist` section the deploy process preloads an attacker shared object into every process the deploy spawns?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `LD_PRELOAD` via a pull request label name (uppercased); the `review.checklist` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `review.checklist` step inherits `LD_PRELOAD` from Command#unbundled_env and preloads an attacker shared object into every process the deploy spawns
- Invariant to test: The `review.checklist` step inherits no fork-controllable key such as `LD_PRELOAD`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `review.checklist` step, inject `LD_PRELOAD` via a pull request label name (uppercased), assert the env reaches the spawned process.
