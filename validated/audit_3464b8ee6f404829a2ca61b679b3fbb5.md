### Title
Webhook signature is validated against the wrong organization's secret, letting an attacker with one org's `webhook_secret` forge events for other repositories - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp`/`webhook_secret` to validate the HMAC signature based on `repository_owner`, which is read directly from the untrusted, unauthenticated request body (`params.dig('repository', 'owner', 'login')`, falling back to `organization.login`). The event handlers that subsequently act on the payload, however, key off a *different* field, `payload.dig('repository', 'full_name')` (or `params.repository.full_name`), to resolve the `Shipit::Repository`/`Stack` to mutate. Because the field used to select the signing secret and the field used to select the target repository are independent and both attacker-controlled prior to signature verification, they can be made to diverge.

### Finding Description
`verify_signature` resolves the signing app like this: [1](#0-0) 

`repository_owner` is derived purely from the JSON body, before any cryptographic check has occurred: [2](#0-1) 

`Shipit.github(organization:)` looks up a *per-organization* config/secret (Shipit supports multi-org config, each org having its own `webhook_secret`): [3](#0-2) 

Once the signature check passes (using whatever secret belongs to `repository_owner`), `create` dispatches the full raw payload — including the `repository.full_name` field — to the registered handlers: [4](#0-3) 

Handlers resolve the acted-upon `Repository`/`Stack` from `repository.full_name`, not from `repository.owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) 

The binding that should hold is: `organization whose secret verified the signature == owner of the repository the handler acts on`. Nothing in the code enforces `repository.owner.login == repository.full_name.split('/').first`, or that the resolved `Repository#owner` matches `repository_owner`. An attacker who controls (or has been given, e.g. as a legitimate but low-privilege member of) one configured organization's `webhook_secret` can craft a payload where `repository.owner.login` (used only for secret selection) names their own org, while `repository.full_name` (used for the actual DB lookup / mutation) names a repository belonging to a *different* configured organization. The HMAC is computed over the raw body with the attacker's own known secret and will validate successfully against `Shipit.github(organization: 'their-org')`, yet the handler will operate on the victim org's `Stack`s (e.g., triggering `stack.sync_github`, PR "review stack" archive/unarchive/creation via `ReviewStackAdapter`, commit status writes, etc.) for a repository the attacker's secret was never issued for.

### Impact Explanation
This breaks the "organization authenticated vs. repository acted on" trust binding described by the review rules. Concretely, with a valid `webhook_secret` for org A but no relationship to org B's repositories, an attacker can:
- Force a resync (`stack.sync_github`) of an arbitrary tracked branch/commit for org B's stacks via `PushHandler`.
- Create/archive/unarchive review stacks for org B's repositories via the PR handlers/`ReviewStackAdapter`, and set commit statuses via `StatusHandler`.

This is effectively unauthorized cross-repository state mutation triggered by a signature that was never issued by (and does not belong to) the repository's real organization — matching "cross-repository writes" in the Critical impact bucket, since deploy/rollback/task creation is ultimately gated on `Stack` state that these handlers can manipulate (e.g., unarchiving stacks, forcing sync to attacker-chosen `after` SHAs which subsequently drives which commits are deployable).

### Likelihood Explanation
Requires the attacker to already possess a valid `webhook_secret` for *any one* configured GitHub organization in the multi-org deployment (e.g., because they are a legitimate integrator on that org, or the secret leaked for that org) but have no privileges on the target org/repository. This is a realistic scenario for Shipit installations that host multiple, mutually-untrusted GitHub organizations (the multi-org config format explicitly exists in `Shipit.github_app_config`/`config/secrets.*.yml` for this purpose). No GitHub App private key, `ApiClient` token, or session is needed — only the webhook secret of one org.

### Recommendation
After successful HMAC verification, cross-check that the organization the payload claims to be from (`repository.owner.login` / `organization.login`) matches the owner segment of `repository.full_name` (and, more robustly, that it matches the owner of the `Repository` record resolved by the handler) before allowing any handler to mutate state. Reject the request (422) if they disagree.

### Proof of Concept
1. Shipit is configured with two orgs in `secrets.github`: `attacker-org` (webhook_secret known to the attacker) and `victim-org` (a completely separate, unrelated org whose stacks the attacker has no access to), per the multi-org config shown in `docs/setup.md` / `config/secrets.development.shopify.yml`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s known `webhook_secret` over the exact raw body (per `Hook::DeliverySigner`/`GitHubApp#verify_webhook_signature` algorithm at `lib/shipit/github_app.rb:76-83`).
4. `WebhooksController#verify_signature` computes `repository_owner == "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and the signature check passes.
5. `create` dispatches the parsed body to `Handlers::PushHandler`, which resolves the target via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` on any matching, non-archived `victim-org/victim-repo` stacks — despite the request never being signed by `victim-org`'s secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
