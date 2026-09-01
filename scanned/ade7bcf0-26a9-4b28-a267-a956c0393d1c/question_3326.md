# Q3326: [prevent_with_label] `PERL5LIB` via a pull request label name (uppercased) affecting the `deploy.override` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `PERL5LIB` through a pull request label name (uppercased) so that when the review stack runs its `deploy.override` section the deploy process adds an attacker perl include path?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `PERL5LIB` via a pull request label name (uppercased); the `deploy.override` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `deploy.override` step inherits `PERL5LIB` from Command#unbundled_env and adds an attacker perl include path
- Invariant to test: The `deploy.override` step inherits no fork-controllable key such as `PERL5LIB`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `deploy.override` step, inject `PERL5LIB` via a pull request label name (uppercased), assert the env reaches the spawned process.
