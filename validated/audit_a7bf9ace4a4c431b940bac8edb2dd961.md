### Title
Webhook signature verified against `repository.owner.login`, but repository state is written based on the untrusted `repository.full_name` field — cross-organization webhook forgery in `WebhooksController` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using an organization name pulled from the **unauthenticated JSON body itself**, while the handlers that subsequently act on that same body select the target `Repository`/`Stack` using a **different field of the same untrusted body** (`repository.full_name`). Because Shipit explicitly supports hosting multiple, mutually-untrusting GitHub organizations behind one instance (each with its own `webhook_secret`), an attacker who legitimately controls one configured organization's GitHub App can forge a webhook payload that authenticates as their own organization but is processed as an event for a *different* organization's repository/stack.

### Finding Description
`verify_signature` computes the authenticating organization from the payload before the signature has been checked: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from `params.dig('repository', 'owner', 'login')` in the raw, unverified JSON body, and is used only to pick which of possibly many configured `webhook_secret`s (one per organization, see `lib/shipit.rb:170-200` and `docs/setup.md:182-209`) must match the HMAC: [3](#0-2) [4](#0-3) 

Once the HMAC check succeeds, `create` hands the *entire same JSON body* to the event handlers: [5](#0-4) 

But every handler determines which `Repository`/`Stack` to mutate using `repository.full_name`, a completely different field of that same body, never cross-checked against `repository.owner.login`: [6](#0-5) [7](#0-6) 

The broken equality is: **`organization whose secret authenticated the request` MUST equal **`organization that owns the repository being written to`, but no such check exists. `repository.owner.login` (used only for signature-secret selection) and `repository.full_name` (used for the actual DB lookup) are independent, attacker-controlled strings in the same unsigned-until-verified body — this is the exact same class of bug as the reported `LimitOrderRegistry::cancelOrder`, where the value validated (`direction`) and the value acted upon (`order.direction`, resolved via a different key) are allowed to diverge.

### Impact Explanation
An attacker who owns/administers *any one* GitHub organization configured on a multi-org Shipit instance (i.e., they legitimately know that organization's `webhook_secret`, which is normal, unprivileged self-service knowledge for their own org's GitHub App settings) can:
1. Craft a JSON body where `repository.owner.login` = their own org (`OrgA`) so `verify_signature` selects `OrgA`'s `webhook_secret` and the HMAC check passes.
2. Set `repository.full_name` = `"OrgB/some-repo"` — an entirely unrelated organization/repository tracked by the same Shipit instance.
3. Sign the crafted body with `OrgA`'s own secret and POST it to `/webhooks`.

Because the handler layer only consults `repository.full_name` (never `repository.owner.login`) to resolve the target `Repository`, this forged, self-signed request is processed as a genuine event for `OrgB`'s stack: e.g. `PushHandler` enqueues a `GithubSyncJob` for `OrgB`'s stack, `Status`/`check_suite` handlers write commit statuses, `membership` handlers create/delete `Team`/`Membership`/`User` rows for `OrgB`'s teams, and pull-request handlers can archive/unarchive or provision review stacks for `OrgB`'s repositories — all triggered by an actor with no relationship to `OrgB` at all. This is a cross-organization write into another tenant's stack state and can force premature/continuous-deployment triggering, satisfying the "cross-repository writes / unauthorized deploy" impact bar defined for this analysis, even though the fetched commit/status content is later pulled from GitHub via `OrgB`'s own credentials (i.e., the attacker controls *when* it happens, not the commit content).

### Likelihood Explanation
This only manifests when a single Shipit deployment is configured with the multi-organization `github:` schema (explicitly documented and supported), and requires the attacker to be a legitimate admin of one of the *other* organizations sharing that instance — a realistic, low-privilege scenario for shared/multi-tenant Shipit installations, and not requiring any Shipit session, `ApiClient` token, or GitHub App private key.

### Recommendation
In `Shipit::WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), require that `repository.owner.login`/`organization.login` used to select the signing secret is the same organization as the owner parsed from `repository.full_name`, and reject the request otherwise before any handler runs.

### Proof of Concept
Given a Shipit instance configured with two orgs, `OrgA` and `OrgB` (per `test/dummy/config/secrets_double_github_app.yml`), and attacker knowing `OrgA`'s `webhook_secret`:

```ruby
payload = {
  ref: "refs/heads/main",
  after: "deadbeef...",
  repository: {
    full_name: "OrgB/some-repo",     # target: a repo/stack the attacker does not control
    owner: { login: "OrgA" }         # used only to select the signing secret
  }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", orgA_webhook_secret, payload)

post "/webhooks", body: payload, headers: {
  "X-Github-Event" => "push",
  "X-Hub-Signature" => signature
}
```

`verify_signature` looks up `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and validates successfully because the attacker legitimately knows `OrgA`'s secret. `PushHandler` then resolves `Repository.from_github_repo_name("OrgB/some-repo")` (from `repository.full_name`) and enqueues `GithubSyncJob` for `OrgB`'s stack — an event the attacker was never authorized to trigger.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
