### Title
Webhook signature verified against the payload's `repository.owner.login`, but the acted-upon repository is resolved from the unauthenticated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to authenticate an inbound webhook based on `params.dig('repository','owner','login')` (or `organization.login`), but every event handler that actually mutates state (`Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name`, and every `PullRequest::*Handler#repository`) resolves the target `Repository` from `params.repository.full_name`, an entirely separate field that is never cross-checked against the value used for signature selection.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` looks up a per-organization secret when Shipit is configured with the multi-org schema documented in `secrets.development.shopify.yml` / `README.md`, where each org can have its own (or no) `webhook_secret`: [2](#0-1) 

`GitHubApp#verify_webhook_signature` is:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

Once `verify_signature` passes, `create` dispatches the raw JSON body, unmodified, to every registered handler for the event:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [4](#0-3) 

Handlers, however, do not resolve the target repository from `repository.owner.login` (the field used for signature routing). They use `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

and identically in every pull-request handler, e.g.:
```ruby
def repository
  @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
end
``` [6](#0-5) 

Because `repository.owner.login` (used to pick the verifying secret/org) and `repository.full_name` (used to pick the repository actually written to) are two independent JSON fields in the same attacker-controlled request body, an attacker who can get any organization's webhook accepted with `verified == true` — e.g., because that org has `webhook_secret: nil` (explicitly shown as an optional/commented-out value in `config/secrets.development.example.yml` and `config/secrets.development.shopify.yml`) or because `Shipit.disable_api_authentication`/dev config leaves it unset — can set `repository.owner.login` to that unauthenticated organization while setting `repository.full_name` to any *other* organization's repository already tracked by the Shipit instance. The signature check binds trust to `repository.owner.login`, but the write path binds to `repository.full_name`; nothing enforces `repository.owner.login == repository.full_name.split('/').first`.

This breaks the intended binding: **organization authenticated == repository written**. The webhook pipeline is designed so that only a request cryptographically tied to organization X can mutate stacks/pull-requests belonging to X's repositories. Because verification and the write-target lookup key off two unrelated fields, an attacker can make a request "authenticated as" a weakly-configured/unsecured organization while its effects land on a repository belonging to a different, properly-secured organization.

### Impact Explanation
Exploiting this lets an unprivileged, unauthenticated caller (needing no `ApiClient` token, no `webhook_secret`, no GitHub App key, and no session) trigger state-changing webhook handlers — e.g. `PullRequest::OpenedHandler` (auto-provisions/unarchives review stacks), `ClosedHandler`/`LabeledHandler` (archives/unarchives review stacks), `MembershipHandler` (creates/removes `Team`/`Membership` records, including cross-referencing arbitrary GitHub logins) — against a `Repository`/`Stack` that belongs to a different, correctly-secured GitHub organization than the one whose (missing or known) secret satisfied `verify_signature`. This is an authentication-bypass class issue: the signature check is satisfied by attacker-controlled data unrelated to the resource being mutated, i.e., the security boundary that "you must present GitHub's HMAC for organization X to touch X's stacks" is not actually enforced per-repository.

### Likelihood Explanation
Requires: (1) the target Shipit instance to have at least one organization configured with the multi-org schema where `webhook_secret` is absent/blank for some org (explicitly the default/example configuration shown in the repo's own docs and example secrets files), and (2) knowledge of the `repository.full_name` of an existing stack in another organization (visible via the public/authenticated Shipit UI or API to any logged-in user, or guessable). No credential or privileged access is needed to construct the forged POST to `/webhooks`. Likelihood depends on deployment configuration (multi-org with an unsecured org entry), which the codebase itself documents and permits as a supported, non-error configuration.

### Recommendation
Bind the two checks: after verifying the signature, re-derive the "owning organization" the same way the handlers resolve the repository (from `repository.full_name`'s owner segment, or from the same field used for verification) and reject the webhook if they don't match. At minimum, `repository_owner` and the repository/organization actually resolved by `Repository.from_github_repo_name` should be required to agree before invoking handlers. Additionally, treat a missing `webhook_secret` for a configured organization as a hard misconfiguration (log/alert) rather than silently returning `true` from `verify_webhook_signature`.

### Proof of Concept
1. Shipit configured with the documented multi-org schema (`config/secrets.development.shopify.yml` style), where `someothergithuborg` has no `webhook_secret` set (as shown blank/optional in the example config).
2. Attacker sends:
```
POST /webhooks
X-Github-Event: pull_request
X-Hub-Signature: sha1=anything   (ignored, since webhook_secret is blank for this org)
{
  "action": "opened",
  "number": 1,
  "pull_request": { ...minimal valid shape... },
  "repository": { "owner": { "login": "someothergithuborg" }, "full_name": "shopify/private-repo" },
  "sender": { "login": "attacker" }
}
```
3. `verify_signature` computes `repository_owner == "someothergithuborg"`, looks up its (secret-less) `GitHubApp`, and `verify_webhook_signature` returns `true` unconditionally.
4. `OpenedHandler` runs and resolves the repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` → `"shopify/private-repo"`, provisioning/mutating a review stack that belongs to the `shopify` organization, entirely disconnected from the org used to pass signature verification. [7](#0-6) [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
