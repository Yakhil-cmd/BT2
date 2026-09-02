### Title
Cross-organization webhook forgery lets any onboarded repository spoof commit statuses for another stack, bypassing CI gating for deploys - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret used to authenticate an incoming GitHub webhook based on `repository.owner.login` (or `organization.login`) taken from the JSON body, while the event handlers that actually mutate state (in particular `StatusHandler`) never re-validate that the payload's `repository` actually corresponds to the organization/stack being written to. `StatusHandler` in fact ignores the repository entirely and updates commits purely by `sha`, matching across every stack in the installation. An attacker who controls any organization/repository onboarded to the same multi-tenant Shipit instance (and therefore knows that org's own `webhook_secret`) can send a validly-signed `status` webhook whose `repository.owner.login` names their own org but whose `sha` is the SHA of a commit belonging to a victim stack, forging a `success` CI status for that commit.

### Finding Description
`verify_signature` resolves the GitHub App/secret to use for HMAC verification from the payload itself: [1](#0-0) [2](#0-1) 

The signature is a valid HMAC over the *entire* raw body using the secret for whichever organization `repository.owner.login` names — but that binds only the payload's *authenticity to that organization's secret*, not the payload's *content* to that organization's actual data. Any handler is free to read a different field of the same payload to decide what to mutate.

`StatusHandler` does exactly that: it looks up commits purely by `sha`, with no repository/stack scoping whatsoever: [3](#0-2) 

Compare this to the base `Handler#stacks`, which scopes lookups by `repository.full_name`: [4](#0-3) 

`StatusHandler` does not use `stacks`/`repository_name` at all — it queries `Commit.where(sha: params.sha)` globally, so a status can attach to a commit belonging to *any* stack in the Shipit instance as long as the `sha` matches (git SHAs of a victim's public/tracked branch are trivially knowable).

Creating a status this way flows into deploy-gating logic: [5](#0-4) [6](#0-5) [7](#0-6) 

So the broken equality is:

`organization authenticated by verify_signature (repository.owner.login)` == `organization/repository whose stack state StatusHandler mutates (matched only by sha)`

Before the attack, these two are implicitly assumed to be the same organization submitting a webhook about its own repository. After the attacker's crafted request, the signature is valid for the attacker's own onboarded org, but the record actually written (`Status`) belongs to a victim's stack in a different organization/repository.

### Impact Explanation
Forging a `success` CommitStatus for a victim commit sets `Commit#deployable?` to true (bypassing required/blocking CI status checks), and `Status#schedule_continuous_delivery` can trigger an automatic deploy of that commit if the victim stack has continuous deployment enabled, or make the commit deployable/mergeable through the UI/API for other users. This is a cross-repository/cross-organization write that results in an unauthorized deploy — matching the "Critical: unauthorized deploy" criterion.

### Likelihood Explanation
Exploitation requires only that the attacker control (or be an admin of) any single organization/repository already onboarded to the same multi-tenant Shipit installation, which is a normal, low-privilege position for a Shipit user (repository onboarding via `RepositoriesController#create` requires only being an authenticated/authorized app user, not any special privilege over the victim's org). The attacker needs the victim commit's SHA, which is public GitHub information for any tracked branch. No access to the victim's own webhook secret, GitHub token, or Shipit session/API token for the victim stack is required.

### Recommendation
`StatusHandler` (and any other handler that does not scope through `Handler#stacks`) must filter matched commits by the stack's repository, and that repository must be derived from — and cross-checked against — the same `repository.full_name`/`owner.login` that was used to select the webhook secret in `verify_signature`. Concretely: change `StatusHandler#process` to scope `Commit` lookups to `stacks` (repository-scoped) rather than a bare `Commit.where(sha:)`, and have `WebhooksController#verify_signature` bind the verified organization to `request` so downstream handlers can assert the acted-upon repository actually belongs to that organization before persisting any state.

### Proof of Concept
1. Attacker owns/administers `attacker-org/attacker-repo`, which is legitimately onboarded to the shared Shipit instance, and therefore knows `attacker-org`'s configured `github.webhook_secret`.
2. Attacker identifies a commit SHA `X` on the victim stack's tracked branch (e.g., `victim-org/victim-repo`), obtainable from GitHub's public commit history or the Shipit UI.
3. Attacker builds a `status` event JSON body:
```json
{
  "sha": "X",
  "state": "success",
  "context": "<required-status-context-of-victim-stack>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/attacker-repo" }
}
```
4. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over the raw body, and POSTs it to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s secret, and the signature validates successfully.
6. `StatusHandler#process` runs `Commit.where(sha: "X")`, which matches the victim's `Commit` record (looked up purely by SHA, independent of `repository.full_name`), and calls `commit.create_status_from_github!(params)`, creating a `success` `Status` for the victim's stack.
7. `Commit#deployable?` now returns true for that commit despite the attacker never having write access to `victim-org/victim-repo`, potentially triggering continuous deployment or letting a subsequent deploy request succeed.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

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
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
