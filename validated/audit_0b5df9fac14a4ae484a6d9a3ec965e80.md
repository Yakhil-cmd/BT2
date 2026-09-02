### Title
Webhook signature verification key is selected from an unsigned field that differs from the field used to route the event, allowing signature bypass and unauthorized team/deploy actions - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization's `webhook_secret` to verify the request against by reading `repository.owner.login` (or `organization.login`) straight out of the **unauthenticated, attacker-supplied** JSON body, before any signature has been validated. The handlers that actually act on the payload (`Shipit::Webhooks::Handlers::Handler#repository_name`, `MembershipHandler`, etc.) resolve the target `Repository`/`Team`/`Stack` from a *different* field of the very same body (`repository.full_name`, `organization.login`, `team.id`). Because these two lookups are never cross-checked, and because `GitHubApp#verify_webhook_signature` trivially returns `true` when the resolved organization has no `webhook_secret` configured, an attacker can pick an organization slug with a blank/unset `webhook_secret` to satisfy `verify_signature`, then supply arbitrary `repository.full_name` / `team` / `member` data that is processed as if it came from GitHub.

### Finding Description
- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` computes:
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
```
`repository_owner` is taken from the raw, not-yet-verified JSON body (`params = JSON.parse(request.raw_post)` happens in `#create`, but `repository_owner` re-parses/reads the same untrusted body during the `before_action`). [1](#0-0) 

- `Shipit.github_app_config(organization)` looks up per-org config by the same untrusted string, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever `webhook_secret` is blank for that org:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) [3](#0-2) 

- Once `verify_signature` passes, `WebhooksController#create` dispatches the same untrusted body to handlers, e.g.:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`repository.owner.login` (used for verification) and `repository.full_name` (used to select which `Repository`/`Stack` gets acted upon) are independent, attacker-controlled fields inside one unsigned JSON blob — the binding "organization whose secret authenticated the request" == "repository the handler writes to" is never enforced.

- This is compounded for the `membership` event, whose handler trusts `organization.login`, `team.*`, and `member.login` wholesale to create/modify `Team`/`Membership` records:
```ruby
def process
  team = find_or_create_team!
  member = User.find_or_create_by_login!(params.member.login)
  case params.action
  when 'added'  then team.add_member(member)
  when 'removed' then team.members.delete(member)
  end
end
``` [5](#0-4) 

Team membership directly feeds Shipit's authorization gate:
```ruby
def authorized?
  @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
end
``` [6](#0-5) 

### Impact Explanation
For any multi-organization Shipit deployment (`secrets.github` keyed by organization, per `Shipit.github_app_config`) where at least one configured organization has no `webhook_secret` set (this field is documented as **optional**, see `docs/setup.md:30`), an unauthenticated attacker can:
1. Send a forged `push`/`status`/`check_suite` webhook naming `repository.owner.login` as the secret-less org, but `repository.full_name` as any repository tracked by Shipit — triggering `GithubSyncJob`, fake commit statuses, or `RefreshCheckRunsJob` for stacks belonging to a completely different (properly-secured) organization.
2. Send a forged `membership` event with `organization.login` set to the secret-less org while supplying a `team` matching one of `Shipit.github_teams`, adding an arbitrary attacker-controlled GitHub login to that team — which is the exact set of teams gating `User#authorized?`, i.e., escalation into `Shipit.github_teams` authorization without ever going through GitHub OAuth.

This satisfies the High-impact category "escalation into `Shipit.github_teams` authorization" and can additionally be leveraged toward unauthorized deploy/rollback triggers via forged `push`/webhook-driven sync events.

### Likelihood Explanation
Requires only: (a) a multi-org Shipit config, and (b) at least one org with `webhook_secret` left blank (explicitly documented as optional) — a realistic, non-exotic operational state, especially for orgs added later or configured hastily. No credentials, sessions, or GitHub App keys are needed; the endpoint is unauthenticated by design (`app/controllers/shipit/webhooks_controller.rb` inherits `ActionController::Base`, not `Shipit::Authentication`).

### Recommendation
- Do not let the field used to select the verification secret differ from the field(s) later trusted to identify the affected resource. At minimum, after choosing the org via `repository_owner`, re-validate that `repository.full_name`'s owner segment matches `repository_owner` before dispatching to handlers.
- Treat "no `webhook_secret` configured" as a hard failure (`head(422)`) rather than an automatic pass in `GitHubApp#verify_webhook_signature`, or require `webhook_secret` to be mandatory per org in `Shipit.github_app_config`.
- For `MembershipHandler`, cross-check `params.organization.login` against `repository_owner`/the verified org before creating/mutating `Team`/`Membership` records.

### Proof of Concept
1. Shipit configured with two orgs in `secrets.github`: `org-a` (has `webhook_secret: s3cr3t`) and `org-b` (no `webhook_secret` set).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "organization": { "login": "org-b" },
  "team": { "id": 48, "name": "Ouiche Cooks", "slug": "ouiche-cooks", "url": "https://example.com" },
  "member": { "login": "attacker-controlled-login" }
}
```
No `X-Hub-Signature` header, or any arbitrary value, is required.
3. `verify_signature` resolves `Shipit.github(organization: "org-b")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request passes.
4. `MembershipHandler#process` creates/finds the `Team` (which can be crafted to match one of `Shipit.github_teams`) and adds `attacker-controlled-login` as a member, as demonstrated by the equivalent legitimate test flow in `test/controllers/webhooks_controller_test.rb:129-165`.
5. If `attacker-controlled-login` corresponds to a GitHub account the attacker controls and later authenticates via Shipit's normal OAuth flow (`GithubAuthenticationController#callback`), `User#authorized?` now returns true due to the forged membership.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
