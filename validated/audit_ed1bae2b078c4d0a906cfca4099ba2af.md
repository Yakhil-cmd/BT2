### Title
Webhook signature verification keys on `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` — enabling cross-organization forged pushes/deploys - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports a multi-tenant GitHub configuration where each organization has its own `webhook_secret`. `WebhooksController#verify_signature` picks *which* secret to verify the HMAC against using `repository.owner.login` (or `organization.login`) from the untrusted JSON payload, but every event handler resolves the actual `Repository`/`Stack` to act on using a *different* payload field, `repository.full_name`, with no check that the two agree. An attacker who legitimately controls one tenant organization's webhook secret can therefore forge a signed webhook whose `owner.login` selects their own organization's secret while `full_name` points at a completely different tenant's repository, causing Shipit to enqueue sync/deploy jobs for a stack that isn't theirs.

### Finding Description
`verify_signature` derives the organization used to fetch the GitHub App/webhook config purely from the payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up per-organization config (`github_app_config`) and the resulting `GitHubApp#verify_webhook_signature` performs an HMAC-SHA1 check of the *entire raw body* against that organization's `webhook_secret`: [3](#0-2) [4](#0-3) 

This design explicitly supports multiple organizations each with independent secrets (`TOP_LEVEL_GH_KEYS`, `github_organizations`, `github_app_config`), confirmed by fixtures configuring several orgs/repos with distinct secrets: [5](#0-4) .

Because the signature is only checked against the secret for the organization named in `repository.owner.login`, and that same field is never cross-checked against `repository.full_name`, an attacker who knows Org A's `webhook_secret` can produce a validly-signed payload where `full_name` names an entirely different Org B repository.

Once `verify_signature` passes, `create` dispatches the raw JSON `params` to all registered handlers for the event, with no re-validation: [6](#0-5) 

Every handler resolves its target purely from `repository.full_name`, independent of the field used for signature verification: [7](#0-6) 

For `push` events specifically, this leads directly to a sync trigger on the resolved stack: [8](#0-7) 

**Binding broken:** organization authenticated (`repository.owner.login` used to select/verify the HMAC secret) ≠ repository written/acted upon (`repository.full_name` used by `Repository.from_github_repo_name` in every handler).

### Impact Explanation
In a multi-org Shipit deployment, this allows a tenant that legitimately owns one organization's webhook integration to forge events that are processed as if they came from any *other* tenant's repository/stack tracked by the same Shipit instance — e.g. triggering `GithubSyncJob` (`stack.sync_github`) or pull-request/review-stack provisioning actions (`opened_handler.rb`, `labeled_handler.rb`, etc.) against a victim tenant's stack. This is a cross-repository write/trigger crossing an organizational trust boundary the system is explicitly designed to keep separate (`Shipit.github_organizations`), matching the Critical "cross-repository writes / unauthorized deploy" bar.

### Likelihood Explanation
Requires: (1) a Shipit instance configured with multiple GitHub organizations/tenants, each with its own webhook secret (an explicitly supported, documented configuration per `lib/shipit.rb`), and (2) the attacker to control/know one tenant's own webhook secret (obtainable legitimately as that tenant's own administrator, without any privileged access to the victim tenant). No `ApiClient` token, session, or GitHub App private key is required — only crafting a raw HTTP POST with a computed HMAC using a secret the attacker already legitimately possesses for their own org.

### Recommendation
After computing `repository_owner` for secret lookup, verify that the resolved `Repository`'s owner matches `repository_owner` (or otherwise bind the two fields together before dispatch), e.g. reject/short-circuit event processing if `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.owner&.casecmp?(repository_owner)` is false. Alternatively, verify signatures using a secret bound to the specific repository/stack (not merely the claimed `owner.login`), and have handlers reuse that same resolved identity rather than re-parsing `full_name` independently.

### Proof of Concept
1. Attacker administers GitHub org `attacker-org`, configured in Shipit as one tenant with `webhook_secret = S_A`.
2. Victim org `victim-org` has a stack/repository tracked by the same Shipit instance under a different tenant config with secret `S_B` (unknown to attacker).
3. Attacker builds a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-controlled sha>",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S_A, raw_body)` and POSTs to `/webhooks`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")`, which loads `S_A`, and the HMAC check passes (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb:76-83`).
6. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`, `app/models/shipit/webhooks/handlers/handler.rb:32-38`), even though the attacker never possessed `victim-org`'s webhook secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** test/fixtures/shipit/github_hooks.yml (L1-25)
```yaml
shipit_push:
  stack: shipit
  event: push
  secret: 1234
  github_id: 42
  type: Shipit::GithubHook::Repo

shipit_status:
  stack: shipit
  event: status
  secret: 1234
  github_id: 43
  type: Shipit::GithubHook::Repo

cyclimse_push:
  stack: cyclimse
  event: push
  secret: 1234
  type: Shipit::GithubHook::Repo

shopify_membership:
  organization: shopify
  event: membership
  secret: 1234
  type: Shipit::GithubHook::Organization
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
