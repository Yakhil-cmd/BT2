# Q5745: [allow_with_label] `RUBYLIB` via a pull request label name (uppercased) affecting the `ci.require` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `RUBYLIB` through a pull request label name (uppercased) so that when the review stack runs its `ci.require` section the deploy process prepends an attacker load path so `require` in a ruby step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `RUBYLIB` via a pull request label name (uppercased); the `ci.require` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `ci.require` step inherits `RUBYLIB` from Command#unbundled_env and prepends an attacker load path so `require` in a ruby step loads attacker code
- Invariant to test: The `ci.require` step inherits no fork-controllable key such as `RUBYLIB`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `ci.require` step, inject `RUBYLIB` via a pull request label name (uppercased), assert the env reaches the spawned process.
