# Q1349: [allow_all] `GIT_TEMPLATE_DIR` via a pull request label name (uppercased) affecting the `machine.environment` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `GIT_TEMPLATE_DIR` through a pull request label name (uppercased) so that when the review stack runs its `machine.environment` section the deploy process supplies a template dir whose hooks are copied into and run on the next `git clone`?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `GIT_TEMPLATE_DIR` via a pull request label name (uppercased); the `machine.environment` section of the fork shipit.yml under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `machine.environment` step inherits `GIT_TEMPLATE_DIR` from Command#unbundled_env and supplies a template dir whose hooks are copied into and run on the next `git clone`
- Invariant to test: The `machine.environment` step inherits no fork-controllable key such as `GIT_TEMPLATE_DIR`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `machine.environment` step, inject `GIT_TEMPLATE_DIR` via a pull request label name (uppercased), assert the env reaches the spawned process.
