### Title
Cross-organization webhook forgery via decoupled signature-org vs. handler-repository binding - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/webhook secret to validate the HMAC signature using `repository_owner`, a value read straight out of the *unverified* JSON body (`payload.dig('repository','owner','login')` or `organization.login`) [1](#0-0) . Once the signature check passes, every event handler independently derives which `Repository`/`Stack` to act on from a *different* field of that same unverified body: `payload.dig('repository', 'full_name')` [2](#0-1) . Nothing ties these two fields together, so the organization whose secret authenticated the request is never checked against the repository the handler actually writes to.

### Finding Description
Shipit supports a multi-tenant GitHub App configuration where each organization has its own `webhook_secret`, as shown in `config/secrets.development.shopify.yml` and implemented by `Shipit.github(organization:)` / `github_app_config` in `lib/shipit.rb` [3](#0-2) .

For an incoming webhook, `WebhooksController#verify_signature` computes:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is `params.dig('repository', 'owner', 'login')` (fallback `organization.login`) [4](#0-3) . This only proves the request body was signed with **that organization's** secret.

The event is then dispatched to handlers (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, `app/controllers/shipit/webhooks_controller.rb:10-15`). Every handler resolves the target `Stack`/`Repository` via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` — a completely independent field of the same body, never cross-checked against `repository_owner` [2](#0-1) . `PushHandler`, for example, uses `stacks` (built from `repository_name`) to trigger `stack.sync_github` and other side effects [5](#0-4) .

This is exactly the binding-equality violation called out in the report class: **organization that authenticated ≠ repository that is written**. An organization "A" that is legitimately configured in this shared Shipit instance (and therefore controls/knows its own `webhook_secret`) can produce a validly-signed webhook body where `repository.owner.login = "A"` (satisfies signature check) while `repository.full_name = "B/some-repo"` (targets an entirely different tenant's repository/stack). The signature never protects the `full_name`/`repository_name` field that handlers actually trust for routing writes.

### Impact Explanation
This breaks tenant isolation between the organizations configured on one Shipit deployment — Org A can forge events attributed to Org B's repositories despite having no access, membership, or credentials for Org B. Depending on which handler fires, this enables cross-repository state manipulation without any Org B credential: e.g. forcing `GithubSyncJob` runs, injecting `Status` records (`StatusHandler`, seen exercised in `test/controllers/webhooks_controller_test.rb:42-59`, which writes `sha/state/target_url/description/context` straight from the payload), manipulating `Team`/`Membership` records via the `membership` event, or affecting pull-request/merge-status handlers scoped to Org B repos — all while the signature only proves the request came from an entity that knows Org A's secret. This falls into the "cross-repository writes" class called out as a Critical-severity impact for this engine.

### Likelihood Explanation
Any organization onboarded to a shared, multi-organization Shipit instance already possesses (or can generate) its own webhook secret, since it is the org itself that configures it when creating its GitHub App per `docs/setup.md`. Crafting a POST to the shared `/webhooks` endpoint with a mismatched `repository.owner.login` / `repository.full_name` pair and a correctly-computed HMAC using its own secret requires no special access beyond that — this is a low-effort forgery once multiple orgs share one Shipit deployment, which is an explicitly documented and supported configuration (`config/secrets.development.shopify.yml`, `TOP_LEVEL_GH_KEYS` handling in `lib/shipit.rb`).

### Recommendation
Bind the field used to select/verify the signing secret to the same field used to resolve the target repository. Concretely, `WebhooksController` should derive `repository_owner` from the same `full_name` used by `Handler#repository_name` (or handlers should re-derive/validate the owner against the org whose secret verified the signature), so a single unforgeable value is used consistently for both authentication and target resolution. Additionally, consider looking up the `Repository`/`Stack` first and confirming its known owner/organization matches the organization that authenticated the signature before invoking any handler.

### Proof of Concept
1. Deploy Shipit with a multi-org GitHub config as in `config/secrets.development.shopify.yml`, containing organizations `orga` and `orgb`, each with its own `webhook_secret`.
2. As a member of `orga` (who knows `orga`'s `webhook_secret`), craft a `push` (or `status`) webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "orga" },
    "full_name": "orgb/private-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orga_webhook_secret, body)>` and POST it to `/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner = "orga"`, fetches `orga`'s `GitHubApp`, and the signature verifies successfully (attacker legitimately knows `orga`'s secret) [6](#0-5) .
5. `PushHandler#process` resolves `stacks` from `repository_name = "orgb/private-repo"` [7](#0-6)  and triggers `stack.sync_github(expected_head_sha: ...)` on `orgb`'s stack — despite the attacker never being authorized against `orgb` at all [8](#0-7) .

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
end
```
