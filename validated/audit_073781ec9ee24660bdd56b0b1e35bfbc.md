### Title
Cross-repository commit-status forgery leads to unauthorized deploy — organization authenticated ≠ repository/commit written - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Shipit's webhook signature check authenticates the request against the **GitHub organization** named in the payload (`repository.owner.login`), but `StatusHandler` — the handler that actually mutates state — never checks that the commit it updates belongs to a repository owned by that organization. Any organization legitimately onboarded to a shared Shipit instance can therefore forge a `status` webhook, correctly sign it with its own `webhook_secret`, and use it to set the CI status of an arbitrary commit SHA belonging to a completely different organization's stack. Because commit status directly drives `deployable?` and continuous-delivery scheduling, this can be used to force an unauthorized deploy of another tenant's stack (or to grief it by marking commits as failing).

### Finding Description
Signature verification is scoped to an organization, taken straight from attacker-controlled payload data: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')`, and `Shipit.github(organization: repository_owner)` picks that organization's `webhook_secret` to validate `X-Hub-Signature`. This only proves the request was signed by *some* organization's configured secret — the org whose login the attacker chose to put in the payload. It does **not** bind the authenticated organization to what the handler subsequently acts on.

The `status` event is dispatched to `StatusHandler`: [3](#0-2) 

Its `params` block requires only `sha`, `state`, and optional description/target_url/context/branches — **no `repository` field at all**, and `process` does `Commit.where(sha: params.sha)` with **no scoping to the organization/repository that was authenticated**. Contrast this with `Handler#stacks`/`#repository_name`, which other handlers (e.g. `PushHandler`) use to scope to `Repository.from_github_repo_name(repository_name)`: [4](#0-3) [5](#0-4) 

`StatusHandler` opts out of this scoping entirely, so the equality that should hold — *organization authenticated by signature == organization owning the repository/commit written* — is broken. The top-level JSON payload can simultaneously contain `repository.owner.login = "attacker-org"` (used only for signature verification) and `sha = "<victim commit sha>"` (used to mutate state), and nothing links the two.

`create_status_from_github!` on the matched commit(s) then updates state and fires deploy-relevant side effects regardless of which org actually owns that commit: [6](#0-5) [7](#0-6) [8](#0-7) 

`deployable?` and continuous delivery both key off status state: [9](#0-8) [10](#0-9) 

### Impact Explanation
An attacker who controls (or is a member of) any organization legitimately onboarded to a multi-tenant Shipit deployment — and therefore knows their own org's `webhook_secret` (a value the org admin configures per `docs/setup.md`) — can sign an arbitrary `status` payload and send it directly to `/github/webhooks`. Because `StatusHandler` never checks that the commit belongs to a repository owned by the authenticated org, the attacker can:
- Mark an arbitrary commit belonging to a **different tenant's stack** as `success` for whatever CI `context` that stack requires, making it `deployable?` and, on stacks with `continuous_deployment` enabled, triggering `trigger_continuous_delivery` → an **unauthorized deploy** of code the attacker does not control.
- Alternatively mark a victim's commits as `failure`/`error` to block their deploys (denial of deploy availability).

This crosses the "unauthorized deploy" / "cross-repository writes" impact bar defined for this engine, achieved purely by an org that is authenticated for its own webhook but never bound to the resource it mutates — the same trust-binding gap as the LenderPool report (an unprivileged/lightly-privileged actor triggers a privileged action on a resource pre-selected by someone else, at a time/target of the attacker's choosing, with no check that the acting party is authorized for that specific target).

### Likelihood Explanation
Requires a Shipit instance configured with more than one GitHub organization (explicitly supported per `config/secrets.development.shopify.yml` and `docs/setup.md`, i.e. a shared/multi-tenant deployment) and requires the attacker to control one such onboarded organization (so they legitimately possess a `webhook_secret` for their own org). Given that, no further privilege is needed — the request bypasses per-repository authorization entirely because `StatusHandler` has no repository check. Target commit SHAs are often guessable/observable (GitHub SHAs, PR pages, status APIs), and `Commit.where(sha: ...)` matches across all stacks store-wide, so a colliding/known SHA is sufficient.

### Recommendation
Scope `StatusHandler#process` to the authenticated repository/organization the same way `PushHandler` does: require and use `repository.full_name` (or the org derived from it) to resolve `stacks`/`Repository.from_github_repo_name`, and only update `Commit` records that belong to stacks under that resolved repository — never query `Commit` by `sha` alone across the whole database. Additionally, have `verify_signature` compare the organization used for signature verification against the organization actually referenced by the handler's target resource, rather than trusting the payload's `repository.owner.login` implicitly for both purposes.

### Proof of Concept
1. Shipit instance is configured with (at least) two organizations, e.g. `attacker-org` and `victim-org`, each with its own GitHub App / `webhook_secret` (as shown supported in `config/secrets.development.shopify.yml`).
2. Attacker is an admin of `attacker-org` and thus knows `attacker-org`'s `webhook_secret`.
3. Attacker identifies a commit SHA `S` belonging to a stack owned by `victim-org` (e.g. observed via GitHub's public commit history or a previous status webhook) that is currently blocking a required CI context, or that they want to force-mark deployable.
4. Attacker crafts a JSON body:
   ```json
   {
     "sha": "S",
     "state": "success",
     "context": "<victim's required CI context>",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
   }
   ```
5. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(attacker-org_webhook_secret, body)` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
6. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, validates the signature successfully against `attacker-org`'s secret.
7. `StatusHandler.call` runs `Commit.where(sha: "S")`, finds the victim's commit (no ownership/organization check performed), and calls `create_status_from_github!`, setting its status to `success`.
8. If `victim-org`'s stack has `continuous_deployment: true`, this either immediately or on the next scheduling tick triggers `trigger_continuous_delivery` → `trigger_deploy`, producing an unauthorized deploy of the victim's stack initiated entirely by the attacker's forged webhook.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
