# Q5704: [allow_with_label] `IFS` via a pull request label name (uppercased) affecting the `rollback.override` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `IFS` through a pull request label name (uppercased) so that when the review stack runs its `rollback.override` section the deploy process changes the shell field separator so a step string re-splits into attacker-chosen argv?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `IFS` via a pull request label name (uppercased); the `rollback.override` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `rollback.override` step inherits `IFS` from Command#unbundled_env and changes the shell field separator so a step string re-splits into attacker-chosen argv
- Invariant to test: The `rollback.override` step inherits no fork-controllable key such as `IFS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `rollback.override` step, inject `IFS` via a pull request label name (uppercased), assert the env reaches the spawned process.
