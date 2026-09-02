### Title
Webhook organization used for HMAC signature verification is decoupled from the repository the webhook payload acts on, enabling cross-repository/cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which HMAC `webhook_secret`) to verify a webhook against based on `repository.owner.login` extracted from the JSON body, but every event `Handler` resolves the actual `Repository`/`Stack` to mutate using the unrelated `repository.full_name` field from the very same body. Nothing binds these two fields together, so a party who legitimately controls the webhook secret for one configured GitHub organization can forge a signed payload whose `repository.full_name` names a completely different, victim-owned repository/stack.

### Finding Description
`WebhooksController` picks the verifying GitHub App config from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization from `secrets.github`, i.e. Shipit is explicitly multi-tenant, each configured GitHub organization owning its own secret: [3](#0-2) 

Once the signature passes, `Handler.call(params)` is invoked for every registered handler. Handlers determine the target repository using a *different* field of the same JSON body — `repository.full_name` — completely independent of `repository.owner.login` used above for secret selection: [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` naively splits `full_name` on `/` and looks the repo up by owner/name, with no cross-check against the organization that was used to authenticate the request: [6](#0-5) 

The same decoupling exists in the pull-request family of handlers (`opened_handler.rb`, `reopened_handler.rb`, `unlabeled_handler.rb`, `edited_handler.rb`, `label_capturing_handler.rb`), all of which resolve `repository` from `params.repository.full_name` while the controller authenticated the request using `params.repository.owner.login` (or `organization.login`) — an entirely separate value from the same signed body: [7](#0-6) 

Because the HMAC covers the raw body as a whole, the signature *is* technically over `full_name` too — but the security property Shipit relies on (“this payload came from GitHub for org X, therefore it's safe to act on repositories belonging to X”) is broken: verification only proves the body was signed with organization X's secret, not that the repository referenced inside that body belongs to X. Any party who legitimately knows one organization's `webhook_secret` (i.e., an admin who configured that organization's GitHub webhook to point at this Shipit instance) can freely fabricate `repository.full_name`/`repository.owner.login` values to target a victim organization's already-configured repository.

### Impact Explanation
This breaks the equality `organization that authenticated the webhook == repository the payload writes to`, matching the allowed “cross-repository writes” Critical impact category. A forged `push` event causes `stack.sync_github(expected_head_sha:)` to run against a victim's stack for a branch/SHA chosen entirely by the attacker; other repository-scoped events (`status`, `pull_request` sub-events, `check_suite`) similarly let the attacker create/modify commit statuses, archive/unarchive review stacks, or otherwise mutate state belonging to a repository outside the organization whose secret was actually used to authenticate the request.

### Likelihood Explanation
Exploitation requires only that the attacker be the legitimate administrator/webhook-configurer of *any one* GitHub organization onboarded to the same Shipit instance (a normal, low-privilege scenario in any multi-tenant Shipit deployment), and that the victim repository is already registered in Shipit. No GitHub App private key, `api_clients_secret`, or Shipit session is needed — only the webhook secret the attacker legitimately possesses for their own org, which is exactly the credential `verify_webhook_signature` is meant to gate on.

### Recommendation
After computing `repository_owner` for secret selection in `WebhooksController#verify_signature`, additionally require that the `repository.full_name`'s owner segment matches `repository_owner` (or, more robustly, resolve the target `Repository` via the app selected for verification and reject if its `owner` differs from the authenticated organization) before dispatching to handlers.

### Proof of Concept
1. Attacker is the configured admin of GitHub organization `attacker-org` in Shipit (`secrets.github[:attacker-org][:webhook_secret] = S`), which they set up themselves when installing the Shipit webhook on their own repo.
2. Attacker crafts a POST to `/github/webhooks` (or the mounted webhook path) with header `X-Github-Event: push` and a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature` as `sha1=` HMAC-SHA1(S, raw_body)` — a valid signature, since `repository_owner` (`attacker-org`) resolves to the App config the attacker legitimately controls: [1](#0-0) .
4. `verify_signature` passes; `PushHandler` looks the target stack up via `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"`, unrelated to the org that was authenticated: [8](#0-7)  and triggers `stack.sync_github(expected_head_sha: params.after)` on a stack the attacker does not own: [9](#0-8) .

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
