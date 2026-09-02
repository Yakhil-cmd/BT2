### Title
Cross-tenant status forgery via `StatusHandler` bypassing repository/organization scoping - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha` with `Commit.where(sha: params.sha)` and never checks that the org/repository whose `webhook_secret` verified the request actually owns the stack containing that commit. Any organization onboarded onto Shipit with its own valid `webhook_secret` can forge a `status` webhook naming a sha that belongs to a different, unrelated tenant's stack, and Shipit will write a `Shipit::Status` row onto that victim commit.

### Finding Description
The broken binding is: `verify_signature` authenticates `payload.dig('repository','owner','login')` (the attacker's own org) equals the org whose `webhook_secret` signs the request — call this org A. But `StatusHandler#process` performs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [1](#0-0)  with no check that `commit.stack.repository`'s owner equals org A. The generic base class `Handler` does define a `stacks` helper scoped by `repository_name` read from `payload.dig('repository','full_name')` [2](#0-1) , and other handlers such as `PushHandler` correctly use this `stacks` scope to filter by the requesting repository [3](#0-2) , but `StatusHandler`'s `params` schema never even requires a `repository` block [4](#0-3)  and `process` bypasses `stacks`/`repository_name` entirely, querying `Commit` globally by `sha`.

`verify_signature` in `WebhooksController` only checks that the signature matches the `webhook_secret` configured for `repository_owner` taken from the same attacker-controlled payload [5](#0-4) ; it does not, and cannot, tie the signature to the specific commit/sha referenced deeper in the payload. Since git commit shas are public and deterministic, an attacker who legitimately owns org A (with its own real `webhook_secret`) can copy a sha they observed in victim org B's public commit history (which Shipit has already ingested as a `Shipit::Commit` for B's stack) and submit a `status` webhook, correctly signed with org A's secret, naming that sha. `StatusHandler#process` finds the matching `Commit` (owned by org B's stack) purely by sha and calls `commit.create_status_from_github!(params)`, which persists a new `Status` via `Status.replicate_from_github!` [6](#0-5) [7](#0-6) , with attacker-controlled `state`, `description`, `target_url`, `context`, and `created_at`.

### Impact Explanation
A forged `Status` on the victim commit can flip `commit.state` to `success`, which is used in `Commit#deployable?` to gate deploys and unblocks merges (`Status#after_create :enable_ci_on_stack` and `after_commit :schedule_continuous_delivery` trigger `ProcessMergeRequestsJob` on the victim's stack, per the transitions tested in `test/models/commits_test.rb`). This is a cross-tenant integrity violation: a payload verified by tenant A mutates tenant B's `Commit`/`Status` state, matching the "Critical" category of "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any commit sha the attacker can observe in any other tenant's public GitHub history, and requires no privilege beyond owning any org already configured in Shipit.

### Likelihood Explanation
Preconditions are modest: the attacker needs their own org already registered in Shipit with a legitimate `webhook_secret` (a normal CI onboarding, not an attacker secret), and needs to know a real commit sha tracked by a victim stack (trivially obtainable from GitHub's public commit history/API for any public repo, or leaked in PR/CI links). No GitHub App private key, no victim `webhook_secret`, and no Shipit session are needed. The cost is a single signed HTTP POST to `/webhooks` with `X-Github-Event: status`, fully repeatable and scriptable against arbitrary victim shas.

### Recommendation
`StatusHandler` should scope its lookup by the requesting repository, mirroring `PushHandler`'s use of `stacks`: require `repository.full_name` in the params schema, resolve `Repository.from_github_repo_name(repository_name)`, and restrict `Commit.where(sha: params.sha)` to `commit.stack.repository_id` (or join through `stacks`) matching that repository, rejecting/ignoring statuses for commits belonging to stacks outside the authenticated repository.

### Proof of Concept
minitest plan (e.g. in `test/models/shipit/webhooks/handlers/status_handler_test.rb` or extending `test/controllers/webhooks_controller_test.rb`):
1. Fixtures: create two `Repository`/`Stack` pairs for org A (`attacker/repo`) and org B (`victim/repo`), each with its own `webhook_secret` configured in `Shipit.github`.
2. Create a `Shipit::Commit` under B's stack with a known `sha`.
3. Build a `status` payload with `sha` = B's commit sha, `state` = `success`, and `repository.owner.login` = `attacker` (org A), signed with org A's `webhook_secret` via `X-Hub-Signature`.
4. POST to `/webhooks` with `X-Github-Event: status`.
5. Assert `victim_commit.statuses.count` increased by 1 and `victim_commit.reload.state == 'success'`, i.e. `commit.stack.repository.owner` (`victim`) never equalled the authenticating org (`attacker`), proving the write crossed tenant boundaries with no rejection.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
