# Q1923: [prevent_with_label] `ENV` via a pull request label name (uppercased) affecting the `deploy.variables` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `ENV` through a pull request label name (uppercased) so that when the review stack runs its `deploy.variables` section the deploy process names a file the shell sources on startup of a deploy step?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `ENV` via a pull request label name (uppercased); the `deploy.variables` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `deploy.variables` step inherits `ENV` from Command#unbundled_env and names a file the shell sources on startup of a deploy step
- Invariant to test: The `deploy.variables` step inherits no fork-controllable key such as `ENV`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `deploy.variables` step, inject `ENV` via a pull request label name (uppercased), assert the env reaches the spawned process.
