# Q4976: [allow_with_label] `LD_PRELOAD` via a pull request label name (uppercased) affecting the `deploy.override` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `LD_PRELOAD` through a pull request label name (uppercased) so that when the review stack runs its `deploy.override` section the deploy process preloads an attacker shared object into every process the deploy spawns?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `LD_PRELOAD` via a pull request label name (uppercased); the `deploy.override` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `deploy.override` step inherits `LD_PRELOAD` from Command#unbundled_env and preloads an attacker shared object into every process the deploy spawns
- Invariant to test: The `deploy.override` step inherits no fork-controllable key such as `LD_PRELOAD`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `deploy.override` step, inject `LD_PRELOAD` via a pull request label name (uppercased), assert the env reaches the spawned process.
