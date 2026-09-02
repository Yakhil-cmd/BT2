### Title
Webhook signature is verified against `repository.owner.login`, but the event is applied to the unrelated repository named in `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate the HMAC signature against using `repository.owner.login` (falling back to `organization.login`), while every `Shipit::Webhooks::Handlers::Handler` subclass resolves the target `Stack`/`Repository` to mutate using a completely different, independently-controlled field: `repository.full_name`. This is the same class of bug as the C4 finding: a value that is authenticated/verified (the organization) is not the same value that is subsequently acted upon (the repository actually written to).

### Finding Description
`verify_signature` computes the org used for signature verification like this: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` picks the `GitHubApp` config (and its `webhook_secret`) keyed by `repository_owner`, i.e. `repository.owner.login`: [3](#0-2) 

Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs the event handler on the raw JSON `params`, never re-checking `repository.owner.login`. Every handler resolves the stacks to act on via `Handler#repository_name`, which reads `repository.full_name` instead: [4](#0-3) 

and looks up the target `Repository`/`Stack` purely from that string: [5](#0-4) 

Nothing in the codebase enforces `repository.full_name.split('/').first == repository.owner.login`. Because `repository.owner.login` and `repository.full_name` are independent JSON fields in the same payload, and the signature only proves "this body was signed with the secret belonging to whatever org `repository.owner.login` names," an attacker who can produce a validly-signed webhook body for Org A's app config can freely set `repository.full_name` to `"OrgB/target-repo"`. The `PushHandler` (and other handlers such as `PullRequest::ClosedHandler`, which independently trusts `repository.full_name` too) will act on `OrgB/target-repo`'s `Stack`, e.g. enqueuing `stack.sync_github(expected_head_sha: params.after)`, even though the signature was never verified with any secret belonging to Org B.

This is exactly the pattern this review explicitly calls out as in-scope: "an organization that authenticated versus the repository that is written."

### Impact Explanation
In a multi-organization Shipit deployment (explicitly supported and documented, see `test/dummy/config/secrets_double_github_app.yml` and `docs/setup.md`'s multi-org config schema), each org has its own `webhook_secret`. A GitHub App installation/webhook belonging to Org A signs payloads with Org A's secret. Anyone able to produce a validly-signed Org-A payload — most simply, an Org A repository administrator configuring Org A's own webhook delivery / replaying it with a modified body against Shipit directly, since `verify_signature` only checks the HMAC of the raw POST body and nothing binds `owner.login` to `full_name` — can set `repository.full_name` to any other organization's tracked repository. This forces `GithubSyncJob` to be enqueued for, and to fetch/mutate commit/stack state of, a repository belonging to a completely separate GitHub organization tenant of the same Shipit instance. This is a cross-repository/cross-tenant write triggered without ever proving control of, or credentials for, the target organization.

### Likelihood Explanation
The break requires no privileged Shipit session, no `ApiClient` token, and no compromise of the target org's secret — only the ability to produce a validly-signed payload for *some* organization configured on the instance (e.g., being a legitimate member/admin able to trigger or replay that org's own webhook deliveries with a modified body, since delivery replays and body forgery are trivial once you hold that org's `webhook_secret`, and multi-tenant Shipit installations are a documented, supported configuration). The vulnerability is a straightforward code-review finding: `verify_signature` and `Handler#repository_name` simply read two unrelated JSON keys and never cross-check them.

### Recommendation
In `WebhooksController`, after signature verification succeeds, assert that `params.dig('repository', 'full_name')&.split('/', 2)&.first&.casecmp?(repository_owner)` (or equivalent) before dispatching to handlers, or have `Handler#repository_name`/`#stacks` reject any repository whose owner does not match the organization whose secret verified the request. The organization used to select the verifying secret must be the same organization bound to the repository the handlers subsequently mutate.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `test/dummy/config/secrets_double_github_app.yml` schema), each with a tracked `Stack` for a repo in their org.
2. Attacker holds/derives a valid signature for a payload whose `repository.owner.login == "OrgA"` (e.g., by replaying/modifying a real Org A webhook delivery body and recomputing the HMAC with Org A's known secret, or by simply being an Org A admin who can control what Org A's webhook sends).
3. Craft the JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha claim>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
4. POST to the webhooks endpoint with `X-Github-Event: push` and `X-Hub-Signature: sha1=<hmac using OrgA's webhook_secret>`.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")` and validates the signature successfully against OrgA's secret. [6](#0-5) 
6. `PushHandler#process` resolves `stacks` via `repository_name` = `"OrgB/target-repo"`, entirely bypassing OrgB's own webhook secret, and enqueues `GithubSyncJob` / `sync_github` against OrgB's stack. [7](#0-6) [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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
