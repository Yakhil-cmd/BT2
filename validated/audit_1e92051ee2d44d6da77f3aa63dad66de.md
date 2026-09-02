## Title
Webhook signature verified against the organization embedded in `repository.owner.login`, while all event handlers act on the unrelated `repository.full_name` — authentication bypass across GitHub organizations - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to check the HMAC signature against using `repository_owner`, a value read straight out of the untrusted, attacker-supplied JSON payload. Every downstream `Shipit::Webhooks::Handlers::Handler` subclass, however, resolves the `Repository`/`Stack` it mutates using a *different* field of that same payload: `repository.full_name`. Nothing ties these two fields together, so the "organization whose credential authenticated the request" and "the repository that is written" are never proven to be the same entity — mirroring the reported bug class where a validation check (`calledExchanges & exchangeBitIndex`) operates on data that no longer represents the invariant it was meant to enforce.

### Finding Description
`verify_signature` picks the signing secret with: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` and `GitHubApp#verify_webhook_signature` then look up config for *that* organization only: [3](#0-2) [4](#0-3) 

Crucially, `verify_webhook_signature` returns `true` unconditionally when that organization's `webhook_secret` is blank/nil — a state explicitly shown as the default in the shipped example configs (`webhook_secret: # nil`) for every organization in a multi-app deployment: [5](#0-4) [6](#0-5) 

Once the (possibly trivially-satisfied) signature check passes, `create` dispatches the *same untrusted payload* to handlers: [7](#0-6) 

Every handler determines the target `Repository`/`Stack` from `repository.full_name`, a completely separate field of the payload that is never cross-checked against `repository.owner.login`: [8](#0-7) [9](#0-8) [10](#0-9) 

Broken invariant (as an equality): `organization_that_authenticated (repository.owner.login) == organization_owning_repository_acted_on (repository.full_name)`. GitHub itself always sends these consistently, but the engine never enforces it, so a forged payload can decouple them.

### Impact Explanation
In a multi-organization Shipit deployment (the documented "Using Multiple Github Applications" configuration), any organization whose `webhook_secret` is blank (the documented default) — or whose secret an attacker otherwise obtains — becomes a skeleton key for *every other organization's stacks configured in the same Shipit instance*. An attacker crafts a payload with `repository.owner.login` set to the weakly-configured org (satisfying `verify_signature`) but `repository.full_name` set to a victim org/repo that has a stack in Shipit. This lets an unprivileged, unauthenticated attacker:
- Force `PushHandler` to trigger `stack.sync_github` for a victim repository.
- Force `pull_request` handlers to provision/archive/unarchive `ReviewStack`s (which run real deploy commands and checkouts) for the victim repository, via `Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter`.
- Trigger `membership`/other handlers against victim-owned data.

This is a cross-repository, cross-organization write achieved purely by exploiting a webhook-signature confusion, satisfying the "cross-repository writes / unauthorized deploy" Critical bar, and directly parallels the report's bug class: a validation gate (`exchangeBitIndex`/signature check) computed from data that doesn't actually correspond to the operation being authorized (duplicate exchange id/`repository.full_name`).

### Likelihood Explanation
Multi-org configuration is a first-class, documented Shipit feature, and the shipped example secrets files default every org's `webhook_secret` to nil, making this trivially reachable in deployments that follow the documented setup and configure at least one low-security org alongside sensitive ones. No credentials, session, or repository write access are required — only knowledge that a Shipit instance uses multiple GitHub Apps and that one of them lacks (or has a leaked) webhook secret.

### Recommendation
Verify the webhook signature using the secret associated with the organization that actually owns `repository.full_name` (or the resolved `Stack`/`Repository`), not the attacker-supplied `repository.owner.login`/`organization.login`. Additionally, reject payloads where `repository.owner.login` does not match the owner segment parsed from `repository.full_name`, and treat organizations with a blank `webhook_secret` as untrusted for cross-account routing purposes.

### Proof of Concept
1. Configure Shipit with two GitHub Apps, `WeakOrg` (no `webhook_secret` set) and `VictimOrg` (properly configured), each with stacks tracked in Shipit.
2. POST to `/github/webhooks` with:
   - `X-Github-Event: pull_request`
   - `X-Hub-Signature`: anything (irrelevant, since `WeakOrg`'s secret is nil)
   - Body: `{"action":"opened","repository":{"owner":{"login":"WeakOrg"},"full_name":"VictimOrg/victim-repo"}, "pull_request": {...}, "sender": {...}}`
3. `verify_signature` resolves `Shipit.github(organization: "WeakOrg")`, whose `verify_webhook_signature` returns `true` unconditionally (blank secret).
4. `OpenedHandler` resolves `Shipit::Repository.from_github_repo_name("VictimOrg/victim-repo")` and provisions/mutates a `ReviewStack` belonging to `VictimOrg`, entirely bypassing `VictimOrg`'s webhook signature verification.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** config/secrets.development.shopify.yml (L6-18)
```yaml
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
