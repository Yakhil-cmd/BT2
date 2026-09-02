### Title
Webhook signature verification authenticates the wrong field: `repository.owner.login` selects the signing key while `repository.full_name` selects the acted-upon Stack — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment (documented in `docs/setup.md` under "Using Multiple Github Applications"), each GitHub organization gets its own `GitHubApp` configuration and its own `webhook_secret` in `secrets.yml`. `WebhooksController#verify_signature` selects *which* organization's secret to verify the incoming payload against using one JSON field (`repository.owner.login` / `organization.login`), while the event handler that actually decides which `Stack` gets acted upon reads a *different*, independently-controlled JSON field (`repository.full_name`) from the very same unverified body. These two fields are never cryptographically bound to each other, so a legitimate owner/admin of Organization A (who knows only Organization A's own `webhook_secret`, because they configured it themselves when integrating their own org) can craft a signed request that is verified as "from Organization A" but whose payload targets an arbitrary `Stack` belonging to Organization B on the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` picks the verification key like this: [1](#0-0) 

`repository_owner` is derived straight from the unauthenticated request body: [2](#0-1) 

`Shipit.github(organization:)` resolves a **per-organization** `GitHubApp`/`webhook_secret` pair from `secrets.yml`: [3](#0-2) 

Once the signature is accepted, `create` dispatches the *same raw JSON body* to the registered handler for the event: [4](#0-3) 

The handler, however, resolves which repository/stacks to operate on using a completely separate field of the same body — `repository.full_name` — not `repository.owner.login`: [5](#0-4) [6](#0-5) 

Because the HMAC signature only proves "this body was signed with Organization A's secret," and Organization A's secret is legitimately known to Organization A's own admin, that admin can freely choose the *content* of the body they sign, including setting `repository.owner.login = "orgA"` (to pass `verify_signature`) while setting `repository.full_name = "orgB/victim-repo"` (to select an arbitrary `Stack` owned by an unrelated tenant). The equality the code implicitly (and incorrectly) assumes is:

```
organization that authenticated the request (repository.owner.login)
        ==
repository/stack the request is allowed to act on (repository.full_name)
```

This equality holds for genuine GitHub-originated webhooks (GitHub always signs with the secret of the app installed on the repo's actual owner, and `full_name` always matches `owner.login`), but it is never enforced by Shipit itself — the controller and the handler independently trust two different, attacker-suppliable fields of one unauthenticated JSON body.

### Impact Explanation
An admin of one tenant organization on a shared/multi-org Shipit instance can forge webhook deliveries (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) that are cryptographically valid for their own organization but that target `Stack`/`Repository` records belonging to a completely different, unrelated organization. For the `push` event this directly triggers `stack.sync_github(expected_head_sha: ...)` on the victim's stack, which — if `continuous_deployment` is enabled — can cause an unauthorized/unexpected deploy trigger on a repository the attacker does not own or have write access to. This is a cross-tenant, cross-repository authorization break: the credential (webhook secret) that authenticates "who you are" is not bound to the resource ("what repository you may write to"), matching the "unauthorized deploy" / "cross-repository writes" impact tier.

### Likelihood Explanation
Exploitation requires nothing beyond what a legitimate organization already possesses under Shipit's own documented multi-org setup: their own organization's `webhook_secret`, which they themselves provision when connecting their org to the shared Shipit instance. No access to the victim organization, no GitHub App private key, no `ApiClient` token, and no Shipit user session are required — only the ability to send an HTTP POST to the shared `/webhooks` endpoint with a payload signed by their own secret. Any multi-tenant Shipit deployment following the documented "Using Multiple Github Applications" pattern is exposed.

### Recommendation
Bind the authenticated organization to the acted-upon resource before dispatching to handlers:
- After `verify_signature` succeeds for organization `O`, require that every repository referenced in the payload (`repository.full_name`, and any nested `repository`/`organization` objects used by handlers) belongs to `O` (e.g., `repository.full_name.split('/').first == O`, case-insensitively), rejecting the request otherwise.
- Alternatively, resolve the target `Repository`/`Stack` first via `owner.login`, and independently verify that `full_name`'s owner segment matches that same owner, so the two "identity" signals extracted from the payload cannot diverge.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`, `orgA` (attacker-controlled) and `orgB` (victim), each with its own `webhook_secret`, per `docs/setup.md`'s "Using Multiple Github Applications" section.
2. As the legitimate admin of `orgA`, construct a JSON `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(orgA_webhook_secret, raw_body)` using the secret legitimately known for `orgA`.
4. POST this body with header `X-Github-Event: push` to `/webhooks`.
5. `WebhooksController#verify_signature` resolves `repository_owner = "orgA"`, fetches `orgA`'s `webhook_secret`, and the signature check passes.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on `orgB`'s stack — an action `orgA` was never authorized to trigger.

Note: I was unable to fully trace `Stack#sync_github` / `GithubSyncJob` internals within the available index (only line-count matches were surfaced, not the bodies) to confirm the exact downstream effects (e.g., whether it can force a deploy of an attacker-chosen SHA versus only re-fetching genuine commit history from GitHub). If you need the precise deploy-trigger semantics confirmed, a full Devin session with file access would be required to read `app/models/shipit/stack.rb` and `app/jobs/shipit/github_sync_job.rb` in full.

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
