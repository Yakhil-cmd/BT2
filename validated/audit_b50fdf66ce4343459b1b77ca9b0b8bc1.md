This confirms the multi-tenant configuration: `Shipit.github_organizations` and `Shipit.github_app_config(organization)` support multiple distinct GitHub organizations, each with its own `webhook_secret` under `secrets.github[organization]`. [1](#0-0)  This is a legitimate multi-tenant setup: an organization admin who has installed the Shipit GitHub App on their own org knows (or receives from GitHub) that org's `webhook_secret`, since it's configured per-organization.

However, `WebhooksController#verify_signature` selects which organization's secret to use for signature verification based on an **unverified** field read from the request body itself, before the signature has been checked:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

Meanwhile, the actual write path (e.g. `PushHandler`, and all `PullRequest::*Handler` classes) resolves the target `Repository`/`Stack` using a *different* payload field, `repository.full_name`, via `Repository.from_github_repo_name`:

```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 
```ruby
def repository
  Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
end
``` [4](#0-3) 

Nothing enforces that `repository.owner.login` (used to pick the verifying secret) is the same tenant as the org portion of `repository.full_name` (used to pick which Stack gets written to). Both fields sit inside the same attacker-supplied JSON body and are independent strings within that body — the HMAC only proves "this exact byte-for-byte body was signed with organization X's secret," it does not bind `repository.owner.login` to `repository.full_name`.

### Analog exploit
An attacker who legitimately administers **their own** GitHub organization/app installation in this same multi-tenant Shipit instance (and thus knows their own org's `webhook_secret`, since it's issued to them when they configure their org's GitHub App) can craft a webhook payload where:
- `repository.owner.login` = `"attacker-org"` (so `Shipit.github(organization: "attacker-org")` is used, whose secret the attacker knows and can produce a valid HMAC for)
- `repository.full_name` = `"victim-org/victim-repo"` (a completely different tenant's repository already registered in Shipit)

The signature check passes because it validates against attacker-org's secret using the raw body the attacker fully controls. [5](#0-4)  Then `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers that resolve the target repository from `repository.full_name`, i.e., the victim's repository. [6](#0-5) 

For `PushHandler`, this lets the attacker forge a `push` event with an arbitrary `after` SHA against a victim stack, triggering `stack.sync_github(expected_head_sha: params.after)`. [7](#0-6)  For `pull_request` handlers (`opened`, `labeled`, `closed`, etc.), the attacker can forge provisioning/archival events against the victim's review stacks, e.g. calling `ReviewStackAdapter.find_or_create!` or `stack.archive!`/`stack.unarchive!` on the victim's `Repository.review_stacks`. [8](#0-7) [9](#0-8) 

This is a genuine analog of the report's bug class ("critical state-changing action gated on a check that doesn't cover all the fields that determine its effect") — the binding broken is: **organization whose secret authenticates the webhook ≠ repository/stack whose state is written by the handler**.

### Caveats / what I could not fully verify
- I could not confirm from the index whether `params.dig` in `repository_owner` reads from Rails' parsed `params` (which would include the JSON body if a JSON parser middleware is active) or some other object — the controller action itself re-parses `request.raw_post` separately as a local variable, which is confusing but doesn't change the vulnerability: whichever source `params` uses, it originates from the same untrusted raw POST body before signature verification.
- Exploitability requires that the deployment is running the multi-tenant `secrets.github[org]` configuration with more than one organization configured (as opposed to the single-org "backward compatibility" mode), since `repository_owner` only matters when `github_default_organization` is non-nil. [10](#0-9)  I did not find code in this engine that prevents an org admin in one tenant from also being a legitimate user in another tenant's Shipit stacks, so cross-repository writes across tenants is the direct impact, satisfying the "cross-repository writes" criterion in scope.

### Title
Webhook signature verification selects the signing organization from an unverified payload field, while handlers act on a different payload field for the target repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` derives the organization used to look up the HMAC secret from `repository.owner.login` in the raw, unverified request body, but the downstream event handlers determine which `Repository`/`Stack` to act on from `repository.full_name` in the same body. The signature only proves the body was signed by whatever org's secret matched `repository.owner.login`; it does not bind that org to the `full_name` value used for authorization/routing.

### Finding Description
`verify_signature` computes `Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` against that org's `webhook_secret`. [5](#0-4)  Handlers such as `PushHandler` and the `PullRequest::*Handler` classes instead resolve the target `Repository` via `params.repository.full_name` (or `payload.dig('repository', 'full_name')`). [3](#0-2)  Both fields are independent strings inside the same attacker-controlled JSON body; the signature does not tie them together. Any tenant organization that legitimately knows its own `webhook_secret` (issued per-organization in the multi-tenant config, see `Shipit.github_app_config`) can forge a self-signed payload naming a different organization's repository in `repository.full_name`. [11](#0-10) 

### Impact Explanation
This breaks the trust boundary between tenants: an attacker with legitimate access to only their own organization's webhook secret can trigger writes against another organization's Stack/Repository records — forged pushes (`stack.sync_github`), forged PR-based review-stack provisioning/archival (`find_or_create!`, `archive!`, `unarchive!`). This is a cross-repository/cross-tenant write via a spoofed but "validly signed" webhook, matching the report's "missing binding between authorization and effect" bug class.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (`secrets.github` configured with multiple org keys) and requires the attacker to control (or be an admin of) at least one configured organization/GitHub App integration — a low bar in any Shipit instance serving multiple teams/orgs, since no cross-org privilege is otherwise required.

### Recommendation
In `WebhooksController#verify_signature`, after verifying the signature, additionally assert that the organization used to select the secret (`repository_owner`) matches the organization prefix of `repository.full_name` (and of `organization.login` when present) before dispatching to handlers. Alternatively, pass the verified `repository_owner` into handlers and require that `Repository.from_github_repo_name` results belong to that verified organization.

### Proof of Concept
1. Deploy Shipit with two configured organizations in `secrets.github`: `attacker-org` (attacker knows its `webhook_secret`) and `victim-org` (hosts `victim-org/victim-repo`, already registered as a Shipit `Repository`/`Stack`).
2. Attacker crafts a `push` webhook JSON body: `{"ref": "refs/heads/main", "after": "<arbitrary sha>", "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}}`.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over this exact body.
4. POST to `/webhooks` with `X-Github-Event: push` and the computed signature. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` and the HMAC check passes. [12](#0-11) 
5. `PushHandler` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack — a write triggered entirely by attacker-controlled data authenticated under the wrong tenant's key. [7](#0-6)

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```
