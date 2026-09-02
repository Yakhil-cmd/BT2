### Title
Webhook signing-organization is not bound to the acted-upon repository, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `webhook_secret` used to validate an inbound webhook based on an **unauthenticated** field pulled out of the request body itself (`repository.owner.login` / `organization.login`), rather than any authenticated channel binding. The event handlers that subsequently act on the same request instead key off a *different* field of the same JSON body (`repository.full_name`) to decide which `Repository`/`Stack` to mutate. Nothing binds "the organization whose secret verified this signature" to "the repository that the handler will act on," so in a multi-organization Shipit deployment a payload can be signed with Org A's secret while declaring a target repository belonging to Org B.

### Finding Description
The controller resolves which `GithubApp` (and therefore which `webhook_secret`) to use for HMAC verification purely from attacker-supplied payload content, before that content has been authenticated: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (including a distinct `webhook_secret` per org) as documented and tested for multi-org installs: [3](#0-2) [4](#0-3) 

Verification itself is a standard HMAC compare of `request.raw_post` against whichever org's secret was selected: [5](#0-4) 

Once verification passes (using the org selected from `repository.owner.login`), `head(422)` is *not* actually returned in a way that halts the request — `verify_signature` calls `head(422)` but does not `return`, and then `create` still runs the handler: [6](#0-5) 

More importantly, the identity used for verification is never carried forward to the business logic. `Webhooks::Handlers::Handler` (the base class used by `PushHandler` and all other handlers) resolves the target `Repository`/`Stack` using a completely separate payload field, `repository.full_name`, with no cross-check against `repository.owner.login`: [7](#0-6) [8](#0-7) 

`Repository#github_app` also re-derives the org from `owner`, independent of whichever org key validated the request: [9](#0-8) 

This breaks the binding: **organization that authenticated the payload == organization whose repository is written**. Concretely, in a multi-org deployment where an attacker legitimately controls (or otherwise knows the `webhook_secret` of) Org A, they can:
1. Craft an arbitrary JSON body with `repository.owner.login: "OrgA"` (so `verify_signature` looks up Org A's `webhook_secret`) and a valid `X-Hub-Signature` computed with that secret.
2. Set `repository.full_name: "OrgB/victim-repo"` inside the same body, where `OrgB` is a different, unrelated organization configured on the same Shipit instance.
3. Set `X-Github-Event: push` and any `ref`/`after` (commit SHA) values.

`verify_signature` succeeds (Org A's secret matches), and `PushHandler` then calls `stack.sync_github(expected_head_sha: params.after)` against `OrgB/victim-repo`'s stack — a repository the attacker never controls and never received a real webhook from GitHub for.

### Impact Explanation
This lets an attacker who only controls one organization's webhook secret forge events attributed to a completely different, victim organization's repositories on the same Shipit instance — an authentication-bypass-class issue (the signature check verifies "a payload signed by *some* configured org," not "a payload legitimately concerning the org/repo it claims to describe"). Depending on which handler is invoked (`push`, `status`, `check_suite`, `membership`, `pull_request`), this can force out-of-band sync jobs, forge commit `Status` records used for CI gating (`StatusHandler`), or manipulate team/membership records (`MembershipHandler`) for a repository/organization the attacker has no legitimate relationship with. Because commit statuses influence `commit.deployable?`, which gates deploys in `DeploysController#create` (`param_error!(:require_ci, ...) if params.require_ci && !commit.deployable?`), forging status webhooks for a victim org's stack can be used to make an otherwise non-CI-passing commit appear deployable, contributing to an unauthorized deploy path.

### Likelihood Explanation
Exploitation requires a multi-organization Shipit deployment (explicitly documented and supported) where the attacker is able to obtain or configure a `webhook_secret` for any one of the configured organizations — e.g., by being an admin of their own GitHub App/organization that is legitimately installed on the same shared Shipit instance. This is a realistic operating model for the documented "Using Multiple Github Applications" setup, since organizations are meant to be mutually untrusted tenants of the same Shipit installation, yet the webhook boundary between them is not actually enforced.

### Recommendation
- Bind webhook verification to the same field used for repository resolution: derive the verifying `GithubApp`/secret and the acted-upon repository from a single, consistent, already-verified value (e.g., only trust `repository.full_name`'s owner for org selection, or verify the signature per-organization and reject if the verified org does not match `repository.owner.login`/`repository.full_name`'s owner).
- Fix the `head(422) unless verified` in `verify_signature` to actually halt the filter chain (`return head(422) unless verified` or use `throw(:abort)`), since currently execution continues into `create` regardless.
- After verification, explicitly assert `params.dig('repository','owner','login') == params.dig('repository','full_name').split('/').first` (case-insensitively) before dispatching to handlers, rejecting mismatches.

### Proof of Concept
Given a Shipit instance configured with two orgs, `OrgA` (attacker-controlled installation) and `OrgB` (victim), with distinct `webhook_secret`s:

```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```

`WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` (per `repository_owner`, `app/controllers/shipit/webhooks_controller.rb:59-62`) and validates successfully against `OrgA`'s secret. `PushHandler` then resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:33-38`) and triggers `stack.sync_github` on the victim's stack — despite the request never having been signed by, or originating from, `OrgB`'s GitHub App/webhook.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```
