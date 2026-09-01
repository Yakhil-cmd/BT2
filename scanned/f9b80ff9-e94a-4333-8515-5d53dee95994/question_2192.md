# Q2192: Forged `push` (ref prefix trick) forces github sync / deploy of a victim stack

## Question
Can an unprivileged attacker POST a `push` webhook that sets `ref` to a value whose `gsub('refs/heads/','')` still equals the victim branch after stripping, so `PushHandler#process` runs `sync_github(expected_head_sha: params.after)` on a non-archived victim stack and appends/deploys commits the attacker did not author?

## Target
- File/function: app/models/shipit/webhooks/handlers/push_handler.rb + app/jobs/shipit/github_sync_job.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: `ref`, `after`, `repository.full_name`; attacker sets `ref` to a value whose `gsub('refs/heads/','')` still equals the victim branch after stripping
- Exploit idea: `PushHandler` resolves stacks via `Repository.from_github_repo_name(full_name)` and syncs by branch; combined with a verification bypass this drives GithubSyncJob against a victim stack
- Invariant to test: A push event may only sync stacks belonging to the repository that authenticated the event.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: forge a push for a victim repo/branch (no-secret org), assert GithubSyncJob enqueued for the victim stack_id with the attacker's `after` sha.
