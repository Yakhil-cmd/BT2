# Q4942: Forged `check_suite` (head_branch match) forces check-run refresh on a victim commit

## Question
Can an unprivileged attacker POST a `check_suite` webhook that sets `check_suite.head_branch` to a victim stack branch, so `CheckSuiteHandler#process` reschedules check-run refresh for a commit in a stack the attacker does not own, consuming the app's GitHub credentials?

## Target
- File/function: app/models/shipit/webhooks/handlers/check_suite_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: `check_suite.head_branch`, `check_suite.head_sha`, `repository.full_name`; attacker sets `check_suite.head_branch` to a victim stack branch
- Exploit idea: `CheckSuiteHandler` selects stacks by branch and commits by SHA and schedules refresh jobs that call the GitHub API with the app token
- Invariant to test: A check_suite event may only touch commits in the repository that authenticated it.
- Expected Immunefi impact: High — SSRF issuing requests carrying the app's GitHub credentials
- Fast validation: minitest: forge the event, assert RefreshCheckRunsJob / schedule_refresh_check_runs! fired for a victim commit.
