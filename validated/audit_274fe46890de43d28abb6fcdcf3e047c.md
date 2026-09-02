### Title
Webhook signature verifies the organization but `StatusHandler` writes commit statuses cross-organization/cross-repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a webhook against the GitHub App/organization derived from the payload's `repository.owner.login` (or `organization.login`), but the `status` event handler that then runs never checks that the commit it mutates actually belongs to that authenticated repository/organization. The binding the signature is supposed to enforce ("this payload was signed by organization X, therefore it may only write to X's repositories") is broken for the `status` event, unlike `push` and `check_suite`, which correctly scope through the repository lookup.

### Finding Description
`verify_signature` selects the GitHub App config to check the HMAC against using the attacker-controlled `repository.owner.login` field of the payload itself: [1](#0-0) [2](#0-1) 

For most events, the handler base class re-derives the repository from `payload.dig('repository', 'full_name')` and scopes all writes to the `Stack`s belonging to that repository: [3](#0-2) 

`PushHandler` and `CheckSuiteHandler` both go through this `stacks` helper, so they stay bound to the organization/repository that signed the request: [4](#0-3) [5](#0-4) 

`StatusHandler`, however, never calls `stacks` or `Repository.from_github_repo_name`. It looks up commits globally by SHA and writes a status onto them regardless of which repository/organization those commits belong to: [6](#0-5) 

`Commit.create_status_from_github!` then persists a `Status` scoped to `commit.stack`, and creating it triggers CI enablement and continuous-delivery scheduling on that stack: [7](#0-6) [8](#0-7) 

The binding that should hold is:
`organization authenticated by verify_signature (payload.repository.owner.login)` == `organization/repository whose commit/stack is mutated by the handler`

For `status` events this equality is never checked — the handler operates purely on `params.sha`, a value entirely outside the scope of what the HMAC signs for correctness of repository ownership (the signature only proves the payload bytes match a given org's secret, not that the `sha` inside belongs to that org's repos).

### Impact Explanation
In a multi-organization Shipit deployment (the documented config format explicitly supports configuring `github:` entries per-organization, each with its own `webhook_secret`/App), any organization onboarded to the shared Shipit instance can send a `status` webhook that: (a) sets `repository.owner.login` to their own org so `verify_signature` picks their own webhook secret and passes, while (b) setting `sha` to a commit SHA belonging to a *different* organization's stack. Because `StatusHandler` performs no repository/stack scoping, it will create a `Status` (e.g., `state: 'success'`) on that unrelated commit. Since `Status` records feed `deployable_status`/CI gating and continuous-delivery scheduling for the target stack, this allows one tenant organization to forge a passing CI status for another organization's stack, potentially unblocking or triggering an unauthorized deploy of a repository the attacker does not control. This is a cross-repository/cross-organization write achieved purely by controlling one legitimately configured (but different) organization's webhook secret — no Shipit session, API token, or GitHub write access to the victim repo is required.

### Likelihood Explanation
This requires the deployment to configure more than one GitHub organization against a single Shipit instance (an explicitly documented and supported configuration in `config/secrets.development.example.yml` and `docs/setup.md`). Any tenant with a legitimately configured, distinct webhook secret for their own org/App can exploit this without any additional privilege escalation — they only need to guess or know a target commit SHA (SHAs are not secret; they are visible via GitHub, Shipit's own commit list UI, or the target stack's public deploy history).

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the repository derived from the authenticated payload, mirroring `PushHandler`/`CheckSuiteHandler`, e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Repository.from_github_repo_name(repository_name)` before touching `Commit`, so a status can never be attached to a commit outside the organization/repository that authenticated the webhook.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` (attacker-controlled GitHub App/webhook secret) and `org-b` (victim), as supported by `config/secrets.development.example.yml`.
2. Attacker computes a valid `X-Hub-Signature` using `org-a`'s webhook secret over a `status` payload where `repository.owner.login = "org-a"` but `sha` is set to the SHA of a real, unmerged commit belonging to a stack under `org-b`.
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` and successfully verifies the signature (`app/controllers/shipit/webhooks_controller.rb:24-38`).
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` with no org/repo filter (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) and finds the `org-b` commit, calling `create_status_from_github!`, creating a forged `success` `Status` on `org-b`'s stack (`app/models/shipit/status.rb:23-33`), influencing that stack's CI/deployability state despite the attacker never authenticating as, or being authorized against, `org-b`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/status.rb (L18-21)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
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
