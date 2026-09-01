# Q2534: [allow_with_label] `BUNDLE_GEMFILE` via a pull request label name (uppercased) affecting the `tasks.<name>.steps` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `BUNDLE_GEMFILE` through a pull request label name (uppercased) so that when the review stack runs its `tasks.<name>.steps` section the deploy process points bundler at an attacker Gemfile whose evaluated code runs?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `BUNDLE_GEMFILE` via a pull request label name (uppercased); the `tasks.<name>.steps` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `tasks.<name>.steps` step inherits `BUNDLE_GEMFILE` from Command#unbundled_env and points bundler at an attacker Gemfile whose evaluated code runs
- Invariant to test: The `tasks.<name>.steps` step inherits no fork-controllable key such as `BUNDLE_GEMFILE`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `tasks.<name>.steps` step, inject `BUNDLE_GEMFILE` via a pull request label name (uppercased), assert the env reaches the spawned process.
