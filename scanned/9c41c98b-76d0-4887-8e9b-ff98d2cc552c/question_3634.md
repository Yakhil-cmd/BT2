# Q3634: [allow_with_label] `SSH_ASKPASS` via a pull request label name (uppercased) affecting the `provision.handler_name` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `SSH_ASKPASS` through a pull request label name (uppercased) so that when the review stack runs its `provision.handler_name` section the deploy process names a program executed to answer ssh password prompts?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `SSH_ASKPASS` via a pull request label name (uppercased); the `provision.handler_name` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `provision.handler_name` step inherits `SSH_ASKPASS` from Command#unbundled_env and names a program executed to answer ssh password prompts
- Invariant to test: The `provision.handler_name` step inherits no fork-controllable key such as `SSH_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `provision.handler_name` step, inject `SSH_ASKPASS` via a pull request label name (uppercased), assert the env reaches the spawned process.
