### Title
Cross-repository status forgery via organization/repository binding confusion in `StatusHandler` - ([File: app/models/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify the incoming signature against using an organization name read straight out of the untrusted JSON body (`repository.owner.login` or `organization.login`), while `StatusHandler#process` never re-checks that field: it applies the payload's `sha`/`state` to `Commit.where(sha: params.sha)` across the *entire* database, with no scoping to the repository/organization that was actually authenticated. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
This is the same bug class as the Stader `StaderOracle` issue: a write operation is keyed by an implicit "current" context (there, the reportable block; here, the authenticated organization) without validating that the data actually being written belongs to that context, so state from two different scopes gets mixed.

- `verify_signature` picks the `GitHubApp` instance — and therefore the webhook secret used for HMAC verification — from `repository_owner`, itself parsed from the attacker-supplied payload (`params.dig('repository','owner','login') || params.dig('organization','login')`). [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that organization: `return true unless webhook_secret`. In multi-organization installations (documented in `docs/setup.md`), it is architecturally possible/likely for some organizations to be configured without a `webhook_secret` (the sample config even ships with `webhook_secret: # nil`). [4](#0-3) 
- Once past that check, `Shipit::Webhooks.for_event('status').each { |handler| handler.call(params) }` dispatches to `StatusHandler`, which does not use the `Handler#stacks`/`repository_name` scoping that other handlers (`PushHandler`, `CheckSuiteHandler`, `pull_request/*`) rely on. Instead it runs a global, unscoped query: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [5](#0-4) [6](#0-5) [7](#0-6) 

Equality that should hold but doesn't: **organization whose credential authenticated the request == organization/repository the write is applied to**. `verify_signature` authenticates against the organization named in the payload; `StatusHandler` then writes a status onto whatever commit row anywhere in the database happens to share that `sha`, regardless of which repository/organization owns that commit. Commit SHAs are public, deterministic git object IDs — an attacker only needs to read the target stack's public commit history to know the exact `sha` to target; they do not need to produce a hash collision.

### Impact Explanation
`Commit#status` (built from `Status::Group.compact`) and `Commit#deployable?` gate continuous delivery and are commonly used to satisfy `required_statuses`/`blocking_statuses` in `shipit.yml`. [8](#0-7)  Injecting a forged `success` status onto a commit in a stack belonging to an organization the attacker has no relationship with can flip `deployable?` to true and trigger `schedule_continuous_delivery`, feeding an unreviewed/failing commit into the continuous-deployment pipeline of a stack outside the attacker's authorization scope. [9](#0-8)  This is an unauthorized-deploy-enabling, cross-organization write, matching the "High/Critical" impact bar (escalation causing an unauthorized deploy) named in scope.

### Likelihood Explanation
Requires only two conditions, both of which are configuration states this engine itself supports, not attacker-obtained secrets: (1) any organization configured on the shared Shipit instance with a blank/absent `webhook_secret` (an explicitly supported configuration shape per `docs/setup.md` and the sample secrets file), and (2) knowledge of a target commit's SHA, which is public on GitHub. No `ApiClient` token, `webhook_secret`, session, or repository write access is needed by the attacker for the organization actually being attacked.

### Recommendation
In `StatusHandler` (and any other handler that doesn't already scope via `stacks`), require the commit's owning repository/stack to match `repository_name`/`repository_owner` from the same verified payload before applying any status. More generally, `WebhooksController#verify_signature` should not merely select a secret by a self-declared organization; it should also bind the verified organization to every downstream mutation so no handler can act on a repository/organization other than the one that was authenticated.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` (no `webhook_secret` set) and `victim-org` (a real, secured Shipit deployment target). This mirrors the documented multi-org config shape. [10](#0-9) 
2. Read `victim-org/some-repo`'s public commit history on GitHub and note a commit SHA `X` that is currently pending/failing CI in the Shipit stack for that repo.
3. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "X",
  "state": "success",
  "context": "ci/whatever",
  "repository": {"owner": {"login": "orgA"}, "full_name": "orgA/anything"}
}
```
No valid `X-Hub-Signature` is required because `orgA` has no configured secret, so `verify_webhook_signature` short-circuits to `true`. [11](#0-10) 
4. `StatusHandler#process` finds the commit with `sha == X` — which actually belongs to `victim-org`'s stack — and calls `create_status_from_github!`, recording a forged "success" status on it. [3](#0-2) [12](#0-11) 
5. If that status satisfies `victim-org`'s stack's required/blocking statuses, `deployable?` becomes true and continuous delivery may deploy the commit. [13](#0-12) [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L219-237)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
