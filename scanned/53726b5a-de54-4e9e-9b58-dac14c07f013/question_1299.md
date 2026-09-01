# Q1299: [allow_all] `BUNDLE_PATH` via a pull request label name (uppercased) affecting the `deploy.override` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `BUNDLE_PATH` through a pull request label name (uppercased) so that when the review stack runs its `deploy.override` section the deploy process redirects bundler to an attacker-populated vendored gem tree that runs on load?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `BUNDLE_PATH` via a pull request label name (uppercased); the `deploy.override` section of the fork shipit.yml under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `deploy.override` step inherits `BUNDLE_PATH` from Command#unbundled_env and redirects bundler to an attacker-populated vendored gem tree that runs on load
- Invariant to test: The `deploy.override` step inherits no fork-controllable key such as `BUNDLE_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `deploy.override` step, inject `BUNDLE_PATH` via a pull request label name (uppercased), assert the env reaches the spawned process.
