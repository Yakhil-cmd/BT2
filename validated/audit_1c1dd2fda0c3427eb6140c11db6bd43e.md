This confirms the analog: `CheckSuiteHandler` (and `PushHandler`) properly scope database writes through `stacks` (repository-scoped via `Repository.from_github_repo_name(repository_name)`), but `StatusHandler#process` at [1](#0-0)  queries `Commit.where(sha: params.sha)` globally, with no repository/stack scoping whatsoever.

### Title
Cross-Repository CI Status Injection via Unscoped SHA Lookup in StatusHandler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The `status` webhook's signature verification is bound to the organization derived from the payload's `repository.owner.login`, but the actual database write performed by `StatusHandler` is not scoped to that repository at all — it matches purely on commit SHA across the entire `commits` table.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` to validate the HMAC signature using `repository_owner`, i.e. `params.dig('repository', 'owner', 'login')` [2](#0-1) . This only proves the webhook was legitimately signed by *some* configured GitHub organization/app — it says nothing about which `Stack`/`Repository` the event is allowed to affect.

Once verified, the handler is dispatched with the raw payload: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .

Every other handler enforces the binding between the verified organization/repository and the record being mutated by scoping through `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)` from the same payload's `repository.full_name` [4](#0-3) . For example, `PushHandler` scopes to `stacks.not_archived.where(branch:)` [5](#0-4)  and `CheckSuiteHandler` scopes to `stacks.where(branch: ...)` before touching `stack.commits` [6](#0-5) .

`StatusHandler`, however, never calls `stacks` and instead does a global lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [1](#0-0) . Any `Commit` row in the entire Shipit database sharing that SHA — regardless of which stack/repository it belongs to — receives the injected status. Since git commit SHAs are content-addressed and reproducible (identical tree, parents, author/committer, timestamps, and message yield an identical SHA regardless of which repository hosts the commit), an attacker who can trigger a genuinely GitHub-signed `status` webhook for **any** repository tracked by the Shipit instance (e.g., by pushing/replicating a commit with a known SHA into a repository they control, then posting a commit status via the GitHub Statuses API) can inject a `success`/`failure` status onto a `Commit` belonging to an entirely different, unrelated stack whose SHA happens to match.

This breaks the trust binding: `organization that authenticated (via HMAC signature) == repository that is written (via Commit lookup)`. The signature proves organization A sent the event; the write instead lands on any commit matching the SHA, which may belong to organization B's stack.

### Impact Explanation
`create_status_from_github!` → `add_status` can flip a commit's aggregated `status` state, which in turn calls `stack.schedule_merges` when the new status becomes `pending` or `success` [7](#0-6) , and also drives the continuous-delivery/merge-queue pipeline for that unrelated stack. This lets an attacker who only has push/commit-status rights on one tracked repository forge a favorable CI status on a commit in a completely different repository/stack, potentially advancing it toward an unauthorized merge or deploy — a cross-repository write into a stack the attacker has no authorization over.

### Likelihood Explanation
Exploitability depends on reproducing an identical SHA in an attacker-controlled repository. This is realistic in common scenarios: forked/mirrored repositories retain identical SHAs for shared history, and Shipit instances that track multiple repositories/organizations (each with independent GitHub Apps/webhook secrets) are an explicit supported configuration (`config/secrets.development.example.yml` shows the multi-org schema) [8](#0-7) . No `ApiClient` token, `webhook_secret`, or Shipit session is required by the attacker — only ordinary write/status access to one tracked GitHub repository, which GitHub itself will faithfully sign and relay.

### Recommendation
Scope `StatusHandler#process` through the same repository binding used by every other handler, e.g. restrict the lookup to `stacks.commits.where(sha: params.sha)` (via `Handler#stacks`, derived from `payload.dig('repository', 'full_name')`) instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Shipit instance tracks `OrgA/repo-x` (stack X) and `OrgB/repo-y` (stack Y), each with its own configured GitHub App/webhook secret per `config/secrets.development.example.yml` multi-org schema.
2. Attacker has commit/status rights on `OrgA/repo-x` only. They arrange for a commit whose SHA collides with an existing tracked commit `C` in stack Y (e.g., by mirroring/forking shared history so the identical commit object exists in both repos).
3. Attacker calls GitHub's Statuses API (`POST /repos/OrgA/repo-x/statuses/:sha`) with `state=success`. GitHub signs and delivers a `status` webhook to Shipit using `OrgA`'s legitimate webhook secret.
4. `WebhooksController#verify_signature` validates the signature against `OrgA` successfully [9](#0-8) .
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, matching commit `C` that belongs to stack Y (`OrgB`), and calls `commit.create_status_from_github!(params)` on it [1](#0-0) , injecting a forged `success` status into stack Y and potentially triggering `schedule_merges` for a stack the attacker never had access to.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
