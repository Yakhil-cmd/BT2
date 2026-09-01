# Q0571: [prevent_with_label] `PERL5OPT` via a pull request label name (uppercased) affecting the `review.checklist` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `PERL5OPT` through a pull request label name (uppercased) so that when the review stack runs its `review.checklist` section the deploy process injects `-M`/`-d` options a perl step honours at startup?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `PERL5OPT` via a pull request label name (uppercased); the `review.checklist` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `review.checklist` step inherits `PERL5OPT` from Command#unbundled_env and injects `-M`/`-d` options a perl step honours at startup
- Invariant to test: The `review.checklist` step inherits no fork-controllable key such as `PERL5OPT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `review.checklist` step, inject `PERL5OPT` via a pull request label name (uppercased), assert the env reaches the spawned process.
