### Title
Webhook signature is verified against the org derived from `repository.owner.login`/`organization.login`, but handlers act on the repository named in `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the `webhook_secret` used for HMAC verification) using `repository_owner`, computed as `params.dig('repository', 'owner', 'login')` (fallback `organization.login`). Every event handler, however, resolves the repository/stack to mutate via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`. These two payload fields are never cross-checked against each other, so the field that authorizes the signature and the field that determines which repository is written to can be made inconsistent.

### Finding Description
In a multi-organization Shipit deployment, each GitHub organization has its own `webhook_secret` configured via `Shipit.github_app_config(organization)` [1](#0-0) , and `Shipit.github(organization:)` instantiates a distinct `GitHubApp` per organization key [2](#0-1) .

The webhook signature check is:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

This picks the secret to validate the signature strictly from `repository.owner.login`. HMAC verification itself is done over the raw JSON body [4](#0-3) , so the signature does prove the whole payload came from whoever holds that org's `webhook_secret` — but it does not prove which repository the payload is "about" beyond that owner-derived selection.

Once verification passes, `create` dispatches the entire raw payload to handlers unchanged:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
end
``` [5](#0-4) 

Every handler resolves the target repository/stack from a **different** field, `repository.full_name`, not from `repository.owner.login`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 
and `Repository.from_github_repo_name` splits that string on `/` to find owner/name independently [7](#0-6) . The same pattern repeats in `PushHandler` (via `stacks`) [8](#0-7)  and in every `PullRequest::*Handler` (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler`, `EditedHandler`), all of which use `params.repository.full_name` to look up the acted-upon repository [9](#0-8) .

**The broken binding, stated as an equality that the code assumes but never enforces:**
`repository.owner.login` (used to select the verifying `webhook_secret`) == owner segment of `repository.full_name` (used to select the repository/stack that gets mutated).

An operator of an org **A** that is legitimately configured in Shipit (and therefore knows/controls org A's `webhook_secret`, e.g. because they are an admin of their own GitHub App/organization webhook settings) can send a request where:
- `repository.owner.login = "org-A"` and `organization.login` absent/`"org-A"` → causes `verify_signature` to fetch and check against org A's secret, which the attacker can correctly compute since they hold it.
- `repository.full_name = "org-B/victim-repo"` → causes every handler to resolve and mutate stacks/pull-requests belonging to `org-B`, an organization the attacker has no relation to and whose secret they don't hold.

This is a legitimate signature (computed with an org-A secret the attacker rightfully knows) that is then used to drive writes/state changes against org-B's registered repositories, because no code anywhere compares `repository.owner.login` to the owner segment of `repository.full_name`.

### Impact Explanation
This breaks the multi-tenant trust boundary between organizations hosted by the same Shipit instance: an org that is legitimately allowed to sign payload for itself can forge events (push syncs, pull-request open/close/label/reopen/edit) against a **different** organization's stacks and review stacks, without ever knowing that organization's `webhook_secret`. Depending on the handler this can trigger `sync_github` deploy pipeline updates, archive/unarchive of review stacks, or PR-state changes on repositories the attacker does not control — i.e., cross-repository/cross-organization writes driven by forged webhook events, which the report's original impact ("out-of-scope binding permits an unauthorized action against an entity different from the one authenticated") is intended to capture (High: escalation into cross-repository state and unauthenticated write of stack state via forged webhooks).

### Likelihood Explanation
Likelihood is High for any deployment using the documented multi-organization `github:` secrets schema (`config/secrets.development.example.yml` shows the multi-org shape) [10](#0-9) . Any party who is an admin of one configured GitHub organization/App (and thus knows that org's webhook secret) can craft this request with no other privilege — no Shipit session, API token, or GitHub write access to the victim org is required, only the ability to compute an HMAC with a secret they legitimately possess and to send an HTTP POST to the public `/webhooks` route [11](#0-10) .

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), enforce that the owner segment of `repository.full_name` matches `repository.owner.login` (or `organization.login`) before dispatching to handlers, and reject (422) on mismatch. Alternatively, derive the org used to select the webhook secret solely from `repository.full_name`'s owner segment so the same field used for authorization is the field used for repository resolution everywhere.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md` multi-org schema).
2. As an administrator of `org-a`'s GitHub App, compute `X-Hub-Signature = sha1=HMAC(org-a-webhook-secret, body)` over a crafted `push` payload where:
   - `repository.owner.login = "org-a"`
   - `repository.full_name = "org-b/victim-repo"`
   - `organization` key absent.
3. POST this body with the computed signature to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "org-a")` and successfully verifies the signature using org-a's secret [12](#0-11) .
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("org-b/victim-repo")` and calls `sync_github` on `org-b`'s stacks [13](#0-12) , despite the attacker never having access to `org-b`'s webhook secret.

### Citations

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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** config/routes.rb (L1-1)
```ruby
# frozen_string_literal: true
```
