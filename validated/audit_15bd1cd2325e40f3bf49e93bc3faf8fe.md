## Title
Webhook signature is verified against the organization named in `repository.owner.login`, but handlers act on the repository named in `repository.full_name` — allowing a legitimately-configured GitHub organization to forge cross-organization webhook events (`WebhooksController#verify_signature`)

### Summary
Shipit exposes a single, global webhook ingestion endpoint (`resources :webhooks, only: :create` in `config/routes.rb`) shared by every configured GitHub organization [1](#0-0) . `Shipit.github_organizations` / `Shipit.github_app_config` show this engine natively supports multiple, independently-configured GitHub Apps (one per organization, each with its own `webhook_secret`) all posting to that same endpoint [2](#0-1) . `WebhooksController#verify_signature` picks *which* organization's secret to verify the HMAC against purely from the payload's `repository.owner.login` (falling back to `organization.login`), and never checks that this owner actually matches the repository the payload claims to modify [3](#0-2) . Every event handler, however, resolves the repository/stack to act on from a *different* field: `payload.dig('repository', 'full_name')`, via `Repository.from_github_repo_name` [4](#0-3) . This is the exact "organization authenticated versus repository written" trust binding the scan targets.

### Finding Description
The binding that must hold is:

`organization used to select verify_webhook_signature secret == owner(repository.full_name) acted on by the handler`

Before the attack: for legitimate GitHub deliveries, GitHub always sends `repository.owner.login` and `repository.full_name` referring to the same repository, so this equality holds implicitly, but Shipit never enforces it explicitly.

After the attack: an attacker who administers their own GitHub organization ("attacker-org") and has legitimately configured *that org's own* GitHub App/webhook secret against this shared Shipit deployment (a first-class, documented configuration — see `docs/setup.md`'s per-org GitHub App setup and `Shipit.github_app_config`) can compute a valid `X-Hub-Signature` using their own known secret, while setting:
- `repository.owner.login` (or `organization.login`) = `"attacker-org"` — used only for secret selection in `verify_signature`.
- `repository.full_name` = `"victim-org/victim-repo"` — used by the handler to select the actual `Repository`/`Stack` to mutate.

`Shipit.github(organization: "attacker-org")` returns the attacker's own `GitHubApp`, whose `verify_webhook_signature` succeeds because the attacker crafted the HMAC with their own secret [5](#0-4) . The request then proceeds to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, and the handler resolves the target using `repository.full_name`, i.e. `victim-org/victim-repo`, which is fully attacker-controlled and never re-validated against the authenticated `attacker-org` [6](#0-5) .

### Impact Explanation
This lets an attacker who legitimately controls only their own GitHub organization's Shipit integration forge webhook events against any other tracked repository/organization:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stacks [7](#0-6) .
- `StatusHandler` creates arbitrary commit statuses (`commit.create_status_from_github!`) on any commit `sha` matching in the datastore, regardless of which repo it belongs to, which can be used to forge a passing CI status (`ci.require`) and unblock an otherwise-gated deploy of the victim stack [8](#0-7) .
- Pull-request handlers similarly resolve `Repository.from_github_repo_name(params.repository.full_name)` and act on PR/review-stack state for any tracked repository [9](#0-8) .

This crosses the repository/authentication boundary explicitly called out as Critical: cross-repository writes and unauthorized deploy triggers, achieved by an attacker with no privilege on the victim organization or repository, only control of their own (separately, legitimately configured) organization's webhook secret.

### Likelihood Explanation
Any Shipit deployment that supports more than one GitHub organization (multi-tenant configuration, explicitly supported via `Shipit.github_app_config`/`github_organizations`) is affected. Any org owner who is entitled to configure their own org's GitHub App against the shared instance can mount this attack against every other organization/repository tracked by that same instance, with no further access needed — no target credentials, no Shipit session, no `ApiClient` token.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), require that the repository named in the resolved `Repository` record (`repository.owner`) matches the organization whose secret validated the signature (`repository_owner`), rejecting the request with 422 otherwise. Concretely, after signature verification succeeds, re-derive the repository owner from `payload.dig('repository', 'full_name')` and assert it equals `repository_owner` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`: `attacker-org` (secret `S_A`, known/controlled by the attacker) and `victim-org` (secret `S_V`, unknown to attacker), both routed through the single `/webhooks` endpoint.
2. Attacker builds a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha in victim repo>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, raw_body)>` using their own known secret `S_A`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and `verify_webhook_signature` succeeds (attacker's own secret matches).
6. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — an action the attacker was never authorized to trigger. [7](#0-6)

### Citations

**File:** config/routes.rb (L14-14)
```ruby
  resources :webhooks, only: :create
```

**File:** lib/shipit.rb (L190-200)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
