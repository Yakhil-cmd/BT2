### Title
Cross-repository commit-status forgery via unscoped SHA lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The webhook signature check in `WebhooksController#verify_signature` authenticates a GitHub `status` event against the GitHub App belonging to the *organization named in the payload* [1](#0-0) , but the handler that processes that event, `Shipit::Webhooks::Handlers::StatusHandler`, never checks that the commit it updates actually belongs to that organization/repository. It looks up commits purely by `sha` across the entire `commits` table and writes a GitHub-supplied status onto every match [2](#0-1) .

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/webhook secret used to validate the HMAC signature based on `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` [3](#0-2) . This correctly proves the request came from *that* organization's GitHub App installation — i.e., it authenticates "organization X sent this status event for its own repositories."

However, `StatusHandler#process` only requires `sha` and `state` and never requires or validates `repository` [4](#0-3) . It resolves the target purely by matching sha across the whole `Commit` table:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
`Commit#sha` is not namespaced or filtered by `stack`/`repository` in this query — `Commit` records `belongs_to :stack` [5](#0-4)  but the lookup in `StatusHandler` ignores this entirely.

This breaks the binding the report's bug class targets: **"an organization that authenticated versus the repository that is written."** The HMAC/webhook-secret check proves the request originated from org X's installed GitHub App, but the code that consumes the verified payload writes to *any* stack in the Shipit database whose commit happens to share the same SHA, regardless of which organization/repository owns that stack. Nothing in the request payload, in `verify_signature`, or in `StatusHandler` cross-checks that the `sha` belongs to a commit under a repository actually owned by the authenticating organization.

Concretely, an attacker who controls (or has push access to) any GitHub repository that Shipit tracks under a legitimately configured GitHub App/org can fabricate a `status` webhook (which GitHub will sign correctly for that org) carrying an arbitrary `sha`. If that `sha` collides with a commit that also exists in a *different* stack (e.g., a shared/forked repository, a commit cherry-picked or identical across two tracked repos, or simply a stack registered twice under different owners), the forged status will be applied to the unrelated stack's commit via `Commit#create_status_from_github!` → `add_status` [6](#0-5)  and [7](#0-6) .

### Impact Explanation
Commit statuses drive deploy gating: `Commit#deployable?` checks `success?` and `blocked?`, which are computed from the statuses recorded on the commit [8](#0-7) , and a successful status can also trigger `stack.schedule_merges` for the merge queue [9](#0-8) . An attacker with control over one authenticated-but-unrelated GitHub org/repo can therefore forge a passing (or failing) CI status against a commit belonging to a stack/repository they have no access to, potentially unblocking that commit for deploy through the merge queue or continuous delivery path — this matches the "unauthorized deploy" impact tier.

### Likelihood Explanation
Exploitability hinges entirely on the attacker being able to produce (or already possess) a git commit whose SHA-1 matches an existing commit in a stack they don't control, then trigger (or have GitHub trigger) a signed `status` webhook referencing that SHA from their own, legitimately configured org. This is not a brute-force SHA-1 collision requirement in all cases — shared/forked repositories, monorepo mirrors, or repositories registered as multiple stacks with overlapping history are realistic scenarios in which the same commit SHA is legitimately present in more than one tracked `Stack`. Because `StatusHandler` performs zero repository-scoping, the risk applies to that entire class of shared-history configurations without requiring any credential compromise or additional privilege — only an already-authorized GitHub App installation for *some* org tracked by the instance.

### Recommendation
Scope the `StatusHandler` (and any equivalent handler that looks up commits by `sha` alone, e.g. `check_suite`) to the repository named in the webhook payload: require `repository.full_name` in the parameter schema, resolve the target `Stack`/`Repository` first (as `PushHandler` already does via `Handler#stacks`/`#repository_name` [10](#0-9) ), and only update commits within that repository's stacks — e.g. `Commit.where(sha: params.sha, stack: repository.stacks)` instead of an unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Configure two GitHub orgs/apps in `secrets.yml`, `org-attacker` and `org-victim`, both tracked by the same Shipit instance (a supported multi-org configuration per `docs/setup.md`).
2. Ensure a commit with SHA `S` exists in a stack tied to `org-victim` (e.g., because the same open-source commit/history is shared, forked, or mirrored into a repo under `org-attacker`).
3. As the owner of `org-attacker`'s repo, cause GitHub to send (or replay) a `status` event referencing SHA `S` with `state: success`; GitHub signs it with `org-attacker`'s webhook secret.
4. `WebhooksController#verify_signature` validates the signature successfully because it only checks that `org-attacker`'s app produced a valid signature for the payload — it does not verify that SHA `S` belongs to a repository owned by `org-attacker` [11](#0-10) .
5. `StatusHandler#process` finds the commit with SHA `S` under `org-victim`'s stack and records the forged `success` status on it, potentially unblocking that commit for deployment [12](#0-11) .

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
end
```

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
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
