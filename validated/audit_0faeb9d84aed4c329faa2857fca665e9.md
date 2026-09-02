### Title
Cross-repository commit-status forgery via unscoped SHA lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an incoming GitHub webhook against the GitHub App/organization named in the payload's `repository.owner.login` (or `organization.login`), but `StatusHandler#process` — the code that actually *acts* on the payload — looks up the target `Commit` by SHA alone, with no scoping back to the repository/organization that was authenticated. The binding `verified_organization == repository_acted_upon` is not enforced for this handler, unlike `PushHandler`/`CheckSuiteHandler`, which do scope to `Repository.from_github_repo_name(repository_name)`.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App config (and thus which `webhook_secret`) to use for HMAC verification based on `repository_owner`, derived from the payload itself: [1](#0-0) [2](#0-1) 

This design is intentional for multi-tenant deployments, as documented for running Shipit against multiple GitHub organizations, each with its own `app_id`/`installation_id`/`webhook_secret`: [3](#0-2) 

Once the signature is verified as belonging to *some* organization, the payload is dispatched to handlers: [4](#0-3) 

The generic `Handler` base class scopes lookups to the repository named in the payload via `repository_name` (`payload.dig('repository', 'full_name')`) and `stacks`: [5](#0-4) 

`PushHandler` and `CheckSuiteHandler` correctly use this `stacks` helper, restricting effects to stacks belonging to the repository named in the (authenticated) payload. However, `StatusHandler` does not use `repository_name`/`stacks` at all — it queries `Commit` globally by SHA, with no repository/organization scoping whatsoever: [6](#0-5) 

Because git commit SHAs are content-addressed and preserved across forks/clones, a commit that is part of a shared open-source ancestry (e.g., a public upstream repo, or a repo forked into multiple GitHub organizations) can have the identical SHA tracked as part of a `Stack`/`Commit` belonging to a *different* organization than the one that triggered the webhook. An attacker who has write/webhook-triggering ability on their **own** organization's repo (which shares history with the victim's tracked repo) can create a `status` event on that shared commit. GitHub signs this webhook correctly using the attacker's own organization's `webhook_secret`, so `verify_signature` passes — it only proves the payload originated from the attacker's own org's installation, not that the commit belongs to that org's repos. `StatusHandler` then applies the forged status to **any** `Commit` row across the entire Shipit database matching that SHA, including one that belongs to a completely different, victim organization's stack: [7](#0-6) 

This is the exact class of bug described in the report by analogy: the value used to *authenticate* the payload (`repository.owner.login`, bound to a specific webhook secret) is never cross-checked against the value that determines what state is actually *mutated* (the globally-scoped commit `sha` lookup), so the binding `authenticated_org == written_repo` silently fails for this handler.

### Impact Explanation
By injecting a forged "success" commit status onto a commit belonging to a victim stack, an attacker can satisfy Shipit's CI-gating logic for deploy readiness (Shipit gates deploys/merges on commit statuses reported via this exact webhook path). This can allow an unauthorized deploy or merge to proceed on a stack/repository the attacker has no legitimate access to, meeting the "unauthorized deploy, rollback or merge" impact bucket.

### Likelihood Explanation
Exploitation requires: (1) the attacker to control or have webhook-trigger access on some GitHub organization/repo tracked by the same Shipit instance (a legitimate but low-privilege scenario in any multi-tenant/multi-org Shipit deployment, which is a documented supported configuration), and (2) a commit SHA shared between the attacker's repo and the victim's tracked repo (realistic for forks of the same upstream project, monorepo mirrors, or shared submodule/vendor commits). No cryptographic break, no secret leakage, and no privileged Shipit session are needed — only the ability to create a legitimately-signed GitHub `status` event referencing a shared SHA.

### Recommendation
`StatusHandler#process` should scope its `Commit` lookup to the repository named in the authenticated payload (mirroring `Handler#stacks`/`repository_name`), e.g., restrict the query to commits belonging to stacks of `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, so status updates can never cross repository/organization boundaries regardless of SHA collisions across forks.

### Proof of Concept
1. Deploy Shipit tracking two organizations, `victim-org/app` and `attacker-org/app-fork` (a fork of `victim-org/app`), each with distinct `webhook_secret`s per the multi-org config documented in `docs/setup.md`. [3](#0-2) 
2. Identify a commit SHA `X` present in both repos' histories (any shared upstream commit, e.g. the fork point), and confirm Shipit has a `Commit` row for `X` under a `victim-org/app` stack.
3. As a collaborator on `attacker-org/app-fork`, create a `status` webhook event for SHA `X` (e.g., via a CI integration or the Statuses API) with `state: success`.
4. GitHub signs and delivers this webhook using `attacker-org`'s `webhook_secret`; `WebhooksController#verify_signature` passes because it only verifies against `attacker-org`'s app. [8](#0-7) 
5. `StatusHandler#process` updates the status of `Commit` `X` globally, including the row under `victim-org/app`'s stack, without ever checking that the payload's `repository.full_name` matches `victim-org/app`. [6](#0-5) 
6. `victim-org/app`'s commit now shows a forged CI-success status, potentially unblocking deploy/merge gating that depends on it.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-35)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
```
