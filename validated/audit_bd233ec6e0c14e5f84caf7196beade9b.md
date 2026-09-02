### Title
Cross-organization CI status forgery via unscoped `sha` lookup in `StatusHandler` bypasses per-organization webhook authentication - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary

### Finding Description
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to use for HMAC verification based on an attacker-controlled field taken from the still-unverified JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `payload.dig('repository','owner','login')` — a field inside the very payload whose signature is about to be checked. The signature/secret used for verification is thus chosen by the attacker, not derived from a value the platform has independently authenticated.

After verification succeeds, the raw parsed JSON is dispatched to handlers unmodified: [3](#0-2) 

`StatusHandler`, unlike other handlers (`PushHandler`, `PullRequest::ClosedHandler`, etc.), never resolves or checks the `repository` object from the payload at all. It writes a CI status purely by matching `sha` globally across every stack in the installation: [4](#0-3) 

The base `Handler` class shows that repository scoping (`repository_name`, `stacks`) exists as a pattern used by other handlers, but `StatusHandler` deliberately (or by omission) doesn't use it: [5](#0-4) 

The commits table is indexed by the composite key `(stack_id, sha)`, not by `sha` alone, confirming that the same commit SHA is expected to legitimately exist across multiple, unrelated stacks (forks, mirrors, shared history, or an attacker pushing byte-identical commit content to their own repository, which is trivial since a Git SHA is a pure content hash). `Commit.where(sha: params.sha)` therefore is not scoped to the repository/organization that the (attacker-chosen) signing secret nominally belongs to.

**The broken binding, as an equality:**
`organization whose webhook_secret authenticated the request` (derived from attacker-supplied `repository.owner.login`) **≠** `stack/repository whose commit status is actually written` (derived only from `sha`, unchecked against `repository.full_name` or any organization).

Before the attacker's request: a legitimate GitHub webhook for organization X can only affect commits under X's stacks, because GitHub computes `X-Hub-Signature` over the exact payload GitHub sends, and the payload's `repository` fields are internally consistent (owner == repo owner).

After the attacker's request: the attacker owns/administers a GitHub organization `attacker-org` that also has a Shipit App/webhook installed (a normal, unprivileged tenant setup for any Shipit installation supporting `Using Multiple Github Applications`, see `docs/setup.md`). The attacker computes a valid `X-Hub-Signature` using `attacker-org`'s own `webhook_secret` (which they legitimately know, since it's their own org's secret), but crafts the JSON body with `repository.owner.login = "attacker-org"` (so `verify_signature` looks up and validates against the secret they control) while `sha` is set to the SHA of a commit that exists on a victim stack in a completely different organization (obtained by pushing identical content to a repo they control, or simply observing the victim's public commit SHA). `verify_signature` passes because the org lookup and the signature match. `StatusHandler#process` then writes a forged `success`/`failure` status onto the victim's commit, because it never checks which organization/repository the status event nominally belongs to.

### Impact Explanation
`Status` creation triggers `schedule_continuous_delivery`, which can automatically trigger a deploy if the victim stack has continuous deployment enabled and the forged status makes the commit `deployable?`: [6](#0-5) [7](#0-6) [8](#0-7) 

An unprivileged attacker who merely controls a GitHub organization onboarded to the same Shipit instance (with no repository write access, no Shipit session, and no privileged account on the victim's org) can therefore forge a passing CI status on a victim's commit and trigger an unauthorized deploy on a stack they have no access to. This satisfies the Critical bar of "an unauthorized deploy."

### Likelihood Explanation
This requires only: (1) an attacker-administered GitHub organization onboarded to a multi-tenant Shipit instance (a normal, documented, unprivileged configuration per `docs/setup.md`'s "Using Multiple Github Applications" section), and (2) the ability to produce a commit whose SHA matches a target commit — trivially achievable by cloning/mirroring the target's public repository content into their own controlled repo, since Git SHAs are pure content hashes. No credentials, session, or write access to the victim repository/organization are needed.

### Recommendation
`WebhooksController#verify_signature` must not use attacker-controlled payload fields to select the verification secret before the signature has been checked; or, at minimum, handlers must independently verify that `repository.full_name`/`repository.owner.login` in the payload actually corresponds to the organization whose secret validated the signature, and every handler (in particular `StatusHandler`) must scope its writes (`Commit.where(...)`) to the stacks belonging to that authenticated repository/organization instead of matching `sha` globally across all tenants.

### Proof of Concept
1. Shipit is configured with multiple GitHub organizations (per `docs/setup.md`), e.g. `attacker-org` and `victim-org`, each with its own App/`webhook_secret`.
2. Attacker mirrors/clones `victim-org/victim-repo`'s HEAD commit into a repo under `attacker-org`, obtaining an identical SHA `S`.
3. Attacker crafts a `status` webhook JSON body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/mirror"}, "sha": "S", "state": "success", "context": "ci/forged"}`.
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org_webhook_secret, body)`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` → verifies using `attacker-org`'s secret → passes. [9](#0-8) 
6. `StatusHandler#process` executes `Commit.where(sha: "S")` which matches the victim's commit in `victim-org/victim-repo`'s stack and calls `create_status_from_github!`, writing a forged success status for that stack, potentially triggering `ContinuousDeliveryJob` on the victim stack. [10](#0-9)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
