### Title
Cross-repository CI status forgery leading to unauthorized merges via `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook against the GitHub App/organization named in the payload's `repository.owner.login` (or `organization.login`), but the `status` event handler that then runs performs its write completely unscoped to that organization or repository, matching commits globally by `sha` across the entire Shipit installation.

### Finding Description
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to HMAC-verify the raw body against using only `repository.owner.login`/`organization.login` from the untrusted JSON payload: [1](#0-0) [2](#0-1) 

This proves only that *some* known, configured organization's secret signed the raw body — it does not bind the verified organization to the repository that the handler subsequently acts on. Most handlers do scope their side effects to the repository named in the payload via `Handler#stacks`/`#repository_name` (`payload.dig('repository', 'full_name')`): [3](#0-2) 

However, `StatusHandler` does not use this scoping at all. It looks up commits **globally by sha**, with no repository/organization filter whatsoever: [4](#0-3) 

This is the same bug class as M-11: one value (`repository.owner.login`) is what is checked/"bounded" by the trust mechanism (HMAC verification), while a different, unrelated payload value (`sha`) is what is actually used downstream to perform a state-changing action, with no cross-validation between the two. In Shipit multi-org deployments (the engine explicitly supports multiple organizations, each with its own `webhook_secret`, as seen in `config/secrets.development.shopify.yml`), any organization already onboarded into a shared Shipit instance can compute a valid signature over an arbitrary payload using its own legitimate `webhook_secret`, but reference a `sha` belonging to a commit tracked under a completely different, unrelated organization/repository's stack.

`Commit#create_status_from_github!` calls into `Status`, which triggers `enable_ci_on_stack`, `schedule_continuous_delivery`, and, on state transitions, `stack.schedule_merges` (via `Commit#add_status`): [5](#0-4) [6](#0-5) 

### Impact Explanation
An attacker who controls one organization already onboarded into a shared Shipit instance (their own legitimate `webhook_secret`, no elevated Shipit privileges needed) can forge a `status` webhook that is validly signed for their own org but references a `sha` belonging to a commit under a victim stack in a different repository/organization on the same Shipit instance. Because `StatusHandler#process` performs no repository scoping, the forged status (e.g. `state: "success"` for a required CI context) is written to the victim's commit, which can flip `Commit#state`, satisfy CI requirements, and invoke `stack.schedule_merges`, contributing to an unauthorized merge/deploy of the victim's stack — a cross-repository write and unauthorized-merge condition, crossing an organizational trust boundary that the webhook signature was supposed to enforce.

### Likelihood Explanation
Requires only that the attacker administers one org/GitHub App already configured in the shared Shipit instance's `Shipit.github` config (a realistic scenario for any Shipit deployment serving multiple teams/organizations, which the engine's own secrets template explicitly supports). No compromise of the victim's credentials, `GITHUB_TOKEN`, or Shipit session is needed — only knowledge of the attacker's own legitimate webhook secret and a target commit `sha` (obtainable from the victim's public commit history/CI logs).

### Recommendation
Scope `StatusHandler#process` (and any other handler acting on payload data) to the repository named in the payload via the same `stacks`/`repository_name` mechanism used elsewhere, and additionally verify that the organization used to authenticate the webhook signature matches the repository owner referenced in the payload, so that the entity used for authentication and the entity acted upon by the handler are cryptographically the same.

### Proof of Concept
1. Attacker is an admin of GitHub org `attacker-org`, which is a legitimate organization configured in the shared Shipit instance's `Shipit.github` secrets with its own `webhook_secret`.
2. Attacker crafts a `status` event JSON body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/some-repo"}, "sha": "<victim-commit-sha>", "state": "success", "context": "ci/required-check"}`.
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org's webhook_secret, raw_body)` and POSTs it to `/webhooks`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (it is legitimately signed with that org's own secret) — see `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no repository check — see `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` — writing a forged `success` status onto the victim commit belonging to an unrelated stack/organization, potentially triggering `stack.schedule_merges` for that victim stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-26)
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
```

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```
