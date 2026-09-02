### Title
`StatusHandler#process` mutates cross-tenant `Commit` rows by matching on `sha` alone, without scoping to the sending repository via `stacks` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::PushHandler#process` scopes every mutation through `stacks.not_archived.where(branch:)`, which is derived from `Repository.from_github_repo_name(repository_name)` (i.e. the repository that actually sent and signed the webhook). `StatusHandler#process` never calls `stacks`, `repository_name`, or `Repository.from_github_repo_name` at all, and instead runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, mutating every `Commit` row across every `Stack`/repository that happens to share that SHA.

### Finding Description
The binding that should hold for every `Handler` subclass is:
`mutated_records ⊆ Repository.from_github_repo_name(payload.dig('repository','full_name')).stacks.{commits|...}`

For `PushHandler#process` this holds: [1](#0-0)  resolves stacks through `Handler#stacks`, which is `Repository.from_github_repo_name(repository_name)&.stacks` [2](#0-1) .

For `StatusHandler#process` it does not hold: it queries `Commit.where(sha: params.sha)` directly with no join, filter, or reference to `stacks`, `repository_name`, or `Repository.from_github_repo_name` [3](#0-2) . The `params` schema for this handler only requires `sha`/`state` and accepts optional fields — it never requires or validates `repository` [4](#0-3) .

`WebhooksController#verify_signature` authenticates *that the webhook came from GitHub for the organization named in the payload* (`repository_owner`) — it does not, and cannot, authenticate that the `sha` in the payload belongs to any particular stack or repository: [5](#0-4) . Once the signature for the attacker's *own* organization/installation checks out, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches straight into `StatusHandler#process` with no cross-repo scoping [6](#0-5) .

Exploit flow: an attacker who owns/controls a repository (e.g. a public fork that shares commit history — and therefore SHAs — with an upstream repository that has a Shipit `Stack`) can cause GitHub to emit a genuinely-signed `status` event for that SHA (setting a commit status on their own repo is an ordinary, unprivileged write to a repo they own). That event is correctly signed for the attacker's own organization/installation and passes `verify_signature`. `StatusHandler#process` then does `Commit.where(sha: <shared_sha>)`, which returns **every** `Commit` row across **every** `Stack` that has ingested a commit with that SHA — including the victim's completely unrelated stack — and calls `commit.create_status_from_github!(params)` on it [7](#0-6) . This write feeds directly into `Commit#status`, `#deployable?`, and `#schedule_continuous_delivery`, which can push the victim's stack toward continuous deployment based on a status entirely fabricated by the attacker's unrelated, self-owned repository [8](#0-7) .

None of the existing guards catch this: `ExplicitParameters` only validates field types, not repository ownership; `verify_signature`/`GitHubApp#verify_webhook_signature` only proves the request came from GitHub for the attacker's own org; there is no `Repository`/`stacks` lookup anywhere in `StatusHandler`, so the "one repo cannot mutate another" invariant that `PushHandler` enforces is simply absent here.

### Impact Explanation
A forged-by-omission `status` payload from a repository the attacker legitimately owns can write `Status` records onto `Commit`s belonging to a stack/repository the attacker does not control, purely because the commit SHA is shared (e.g. via forking). This is repeatable against any victim repo whose history overlaps with an attacker-controlled repo, and can influence `deployable?`/`blocked?` and trigger `ContinuousDeliveryJob` for the victim's stack — i.e., a payload for one repository mutating another repository's commit/stack state and potentially causing an unauthorized deploy. This matches the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy").

### Likelihood Explanation
Preconditions: the attacker needs a GitHub repository they control whose commit history shares at least one SHA with a victim repository that has an active Shipit `Stack` (trivially true for any fork made before or shortly after divergence, or for repos that share commits via cherry-pick/subtree), and that attacker-owned repository/organization must have GitHub's webhook delivery configured to Shipit's endpoint (satisfied whenever the attacker's own org/repo has the Shipit GitHub App/webhook installed, which is an ordinary, unprivileged action available to any repo owner). No Shipit secrets, sessions, or `api_clients_secret` are required — only ownership of an ordinary GitHub repository. This is low-cost and repeatable per shared SHA.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` does: resolve the sending repository via `Repository.from_github_repo_name(repository_name)`, restrict the query to `stacks.commits.where(sha: params.sha)` (or join `Commit` to `Stack`/`Repository` and filter on the repository that sent the webhook) before calling `create_status_from_github!`, rather than matching on `sha` globally across all tenants.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`-style, no live GitHub):
1. Create `stack_victim` for `repository_name: 'victim-org/app'` and `stack_attacker` for `repository_name: 'attacker/app-fork'`.
2. Create `commit_victim = Commit.create!(stack: stack_victim, sha: 'deadbeef' * 5 ...)` and `commit_attacker = Commit.create!(stack: stack_attacker, sha: <same sha>)` to simulate shared git history.
3. Build a `status` payload whose `repository.full_name` is `'attacker/app-fork'` and `sha` equals the shared sha, with `state: 'success'`.
4. Assert equality before: `commit_victim.status.state != 'success'`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
6. Assert `commit_victim.reload.status.state == 'success'` even though the payload's `repository.full_name` was `attacker/app-fork`, proving cross-tenant mutation.
7. Additionally assert `StatusHandler.new(payload).method(:process).owner.instance_method(:stacks)` is never invoked (e.g. `Shipit::Webhooks::Handlers::Handler.any_instance.expects(:stacks).never` around the `call`), showing the scoping mechanism available in `PushHandler` is structurally absent from `StatusHandler`.

### Citations

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
