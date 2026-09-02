### Title
Webhook signature is validated against an attacker-chosen organization while the event payload's repository/commit target is never bound to that organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using a value taken directly from the **unverified** JSON body (`repository.owner.login` / `organization.login`), before the signature has been checked. Once the signature validates against that attacker-selected organization's secret, the payload is dispatched to handlers that resolve the actual target stack/commit from other unverified fields in the same body (`repository.full_name`, or in the case of `StatusHandler`, only `sha` with no repository check at all). The organization whose secret authenticated the request is never bound to the repository/commit that is actually mutated.

### Finding Description
`verify_signature` computes `repository_owner` from the raw, unverified request body and uses it to pick the app config to check the signature against: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (including `webhook_secret`) keyed by exactly this attacker-controlled string, in multi-tenant deployments where `secrets.github` holds one config block per organization: [3](#0-2) 

The signature is only checked against the secret of the organization named in the payload — nothing ties that organization to the repository/commit the event will actually operate on. Handlers resolve their target purely from other unverified body fields: [4](#0-3) 

Worse, `StatusHandler` doesn't even use the repository field — it matches by commit `sha` alone across the entire Shipit instance: [5](#0-4) 

So the binding an unprivileged attacker breaks is:
`organization whose webhook_secret authenticated the request` ≠ `repository/commit that the dispatched handler actually writes to`.

Concretely, an attacker who is an admin/maintainer of **any one** organization configured in this Shipit instance (and therefore legitimately knows that organization's own GitHub App `webhook_secret`, which they control since they configure/install the app themselves) can:
1. Build a `status` event payload with `repository.owner.login` = their own org (so `verify_signature` picks their own org's secret) and sign it with `X-Hub-Signature` using that secret.
2. Set `sha` to the SHA of a commit belonging to a completely different, victim organization's stack tracked by the same Shipit instance.
3. POST it to `/github/webhooks`. The signature check passes (their own valid secret), and `StatusHandler#process` finds the victim's `Commit` purely by `sha` and calls `create_status_from_github!`, setting state to `success`.

### Impact Explanation
Setting a commit's status to `success` via `Commit#create_status_from_github!` feeds into `Commit#add_status`, which can flip `deployable?`/`simple_state`, fire `deployable_status` hooks, and call `stack.schedule_merges` — enabling continuous deployment to trigger, or clearing a required-status gate that a maintainer relies on before shipping, for a stack the attacker has no legitimate access to. [6](#0-5) [7](#0-6) 

This can result in an unauthorized deploy of a victim organization's stack, which the rubric classifies as Critical impact. The same organization/repository binding gap also lets an attacker with one org's secret inject `push`/`check_suite` events that reference another organization's `repository.full_name`, causing `PushHandler`/`CheckSuiteHandler` to run `sync_github`/`schedule_refresh_check_runs!` against stacks they don't control.

### Likelihood Explanation
Requires the attacker to control (or have configured) one organization's own webhook secret within a multi-tenant Shipit deployment (`secrets.github` keyed by multiple organizations) — a realistic scenario for shared/hosted Shipit instances serving multiple orgs. No repository write access, GitHub App private key, or Shipit session/API token is needed. This is a design flaw in how `verify_signature` binds secret-selection to the event's target, not a misconfiguration.

### Recommendation
- Verify the webhook signature only after confirming the event's `repository.full_name`/`sha` actually belongs to a stack/repository registered under the organization whose secret validated the signature.
- Have `StatusHandler` (and other handlers) scope lookups by repository/organization, not solely by `sha`, and reject events whose declared owner doesn't match the resolved repository's actual owner.
- Consider using GitHub's per-installation webhook secrets tied 1:1 to the installation, and validate that the installation ID in the payload matches the organization config used for verification.

### Proof of Concept
1. Attacker is an admin of `Shipit.github_organizations` member `attacker-org`, and therefore knows `secrets.github[:attacker_org][:webhook_secret]`.
2. Attacker crafts:
```json
{
  "sha": "<victim commit sha from OtherOrg/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker_org_webhook_secret, body)` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, loads that org's `GitHubApp`, and `verify_webhook_signature` succeeds using the attacker's own valid secret. [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim commit regardless of organization — and marks it `success`, potentially triggering deploy scheduling on the victim's stack. [8](#0-7)

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
