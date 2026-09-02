### Title
Webhook signing-secret is selected using an unverified field of the same payload it authenticates, allowing cross-organization event spoofing - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization deployments, `WebhooksController#verify_signature` picks which GitHub App/webhook secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the *unverified* JSON body, while the downstream handlers act on a *different* field of that same unverified body (`repository.full_name`) to decide which tracked repository/stack the event applies to. An attacker who controls one organization onboarded to the same Shipit instance can sign a forged payload with their own known webhook secret while setting `repository.full_name` to a victim organization's repository that Shipit also tracks, causing Shipit to accept and process the event as if it came from the victim's GitHub App installation.

### Finding Description
`verify_signature` derives the signing organization purely from payload content, before any signature has been validated: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization `webhook_secret` from `secrets.github` when multiple GitHub Apps are configured (the documented "Using Multiple GitHub Applications" setup): [3](#0-2) 

The verification therefore checks: *"was this raw body HMAC-signed with the secret belonging to `repository.owner.login`?"* — a field fully controlled by the attacker in the untrusted body. Meanwhile, the actual repository/stack that the event is applied to is resolved from a **different** field of the same untrusted body, `repository.full_name`: [4](#0-3) 

and, e.g., in the pull-request handler used to auto-provision review stacks: [5](#0-4) 

Because the field used to select the verifying secret (`repository.owner.login` / `organization.login`) is not required to match the field the handlers act on (`repository.full_name`), the equality the system implicitly relies on —

`organization whose secret authenticated the request == organization owning the repository the handler mutates`

— is never enforced. An attacker who has their own GitHub organization/App installed on the same Shipit instance (a normal, unprivileged multi-tenant configuration explicitly documented in `docs/setup.md`) knows their own `webhook_secret`. They can send a POST to `/webhooks` with:
- `X-Hub-Signature` computed with **their own** organization's webhook secret,
- `repository.owner.login` = their own org (so `Shipit.github(organization: ...)` picks their own, known secret and verification passes),
- `repository.full_name` = `victim-org/victim-repo` (a repository/stack actually tracked by Shipit under a different, victim organization).

The signature check passes (it only proves the attacker knows their own org's secret), yet the event is dispatched and processed against the victim repository's stacks, e.g. queuing `GithubSyncJob`, creating `Status` records, or triggering the `PullRequest::OpenedHandler` review-stack auto-provisioning flow tied to the victim repository.

### Impact Explanation
This breaks the trust boundary between organizations hosted on a shared Shipit instance: an org that authenticated (proved control of its own webhook secret) is not the same org whose repository/stack state is written. Depending on which webhook event/handler is triggered, this can:
- Force spurious `GithubSyncJob`/`RefreshCheckRunsJob` runs against a victim's stack,
- Inject forged commit `Status` records used for deploy gating on the victim's stack,
- Auto-provision or influence review-stacks for pull requests on a repository the attacker does not own,
- More generally, inject attacker-controlled webhook data into another tenant's stack processing pipeline without needing that tenant's actual GitHub App/webhook secret.

This is a cross-tenant/cross-repository write achieved purely by controlling one legitimately (but separately) configured organization — it does not require compromising the victim's GitHub App, webhook secret, or GitHub account, satisfying the "cross-repository writes" criterion, though the severity is capped by what individual webhook handlers do (it is not RCE or credential exfiltration).

### Likelihood Explanation
Requires the multi-organization GitHub App configuration (`config/secrets.yml` `github:` keyed by org, as documented in `docs/setup.md`), which is an explicitly supported and documented deployment mode, not a misconfiguration outside the engine's scope. Any attacker who controls one of the configured organizations (i.e., can install/administer their own GitHub App with a known webhook secret) — a normal, unprivileged actor relative to other tenants on the same Shipit instance — can exploit this without further access.

### Recommendation
After signature verification succeeds, cross-check that the organization used to select the verifying secret (`repository.owner.login`/`organization.login`) matches the actual owner encoded in `repository.full_name` (and any other identifiers handlers key off of) before dispatching to handlers; reject the request if they diverge. Alternatively, always compute `repository_owner` strictly from `repository.full_name`'s owner segment so the same trusted value is used both to select the verifying secret and to route to handlers.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App / `webhook_secret` (per `docs/setup.md`'s multi-org example), where `victim-org/victim-repo` is a tracked Shipit repository/stack.
2. As the operator of `attacker-org` (or anyone who knows `attacker-org`'s `webhook_secret`), craft a `push` (or other handled) webhook JSON body with:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
3. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(attacker-org webhook_secret, raw_body)`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")`, verifies successfully against the attacker's own secret, and the request proceeds to `Shipit::Webhooks.for_event('push')`, whose handler resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` — acting on the victim's stack despite the request never being signed by `victim-org`'s GitHub App.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-53)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end

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
```
