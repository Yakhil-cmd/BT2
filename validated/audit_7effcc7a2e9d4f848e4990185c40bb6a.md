### Title
Webhook signature verification selects the GitHub App/secret from an attacker-controlled organization field that is decoupled from the repository the event actually operates on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App (and thus which HMAC secret) validates the inbound webhook based on `repository_owner`, a value read straight out of the unauthenticated JSON body (`repository.owner.login`, falling back to `organization.login`). The event handlers, however, resolve the target `Repository`/`Stack` from a *different* field of the same payload: `repository.full_name` [1](#0-0) . Because Shipit explicitly supports multiple GitHub organizations, each with its own `webhook_secret`, this creates a binding mismatch: `organization_that_authenticated == organization_derived_from(repository.owner.login)` while `repository_written_to == organization_derived_from(repository.full_name)`. These two need not be the same organization for the signature check to pass.

### Finding Description
The signature check is:
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

`Shipit.github(organization:)` resolves per-organization app configs (and secrets) as documented for "Using Multiple GitHub Applications" [3](#0-2) , and this feature is explicitly supported/configured this way in production [4](#0-3) .

Every handler, though, resolves the actual `Repository`/`Stack` acted on from a *different* JSON key:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [1](#0-0) 

`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc. all inherit this lookup [5](#0-4) [6](#0-5) .

Nothing enforces that `repository.owner.login` (used to pick the verifying secret) matches the owner implied by `repository.full_name` (used to pick the target stack). All organizations share the same `/webhooks` endpoint, so an attacker who legitimately controls (or has created) their own GitHub App/organization — call it `orgA`, whose `webhook_secret` they know — can send a POST to `/webhooks` with:
- `repository.owner.login = "orgA"` → signature is verified against `orgA`'s known secret and passes.
- `repository.full_name = "orgB/victim-repo"` → the handler acts on `orgB`'s stack, whose real webhook secret the attacker never had.

This is the same class of bug as the GroupBuy finding: a value used for the trust check (`pool.success`/here, the signing organization) is not the same value later acted upon (the purchase market/here, the repository actually written to), letting an attacker satisfy the check with one identity while causing effects against another.

### Impact Explanation
With a forged `push` event pointed at `orgB/victim-repo`, the attacker can trigger `GithubSyncJob` for any stack of that repository via `PushHandler#process` → `stack.sync_github(expected_head_sha:)`, and with continuous deployment enabled this can enqueue/trigger deploys of arbitrary (attacker-chosen) commits without ever holding a credential for `orgB`. A forged `status` event lets the attacker inject fabricated CI statuses (`StatusHandler#process` → `commit.create_status_from_github!`), which can satisfy `ci.require` gates and unblock the merge queue/deploy for a repository the attacker has no access to. This is an unauthorized deploy resulting from crossing an organizational credential boundary — matching the "unauthorized deploy" / "cross-repository writes" impact bar.

### Likelihood Explanation
Requires a Shipit installation configured with multiple GitHub organizations (a documented, supported configuration) where the attacker controls at least one of the configured organizations/apps (e.g., a "bring your own repo" or multi-tenant Shipit deployment). Given that setup, no additional access is needed: the attacker only needs to know their own org's webhook secret (which they legitimately have) and craft a payload with mismatched `owner.login` vs `full_name`. No GitHub App private key, `ApiClient` token, or session is required — this is exactly the kind of unprivileged-attacker, credential-boundary-crossing bug in scope.

### Recommendation
Bind signature verification to the same identity used for repository resolution. Concretely, derive `repository_owner` from the same field used by `Handler#repository_name` (i.e. parse the owner out of `repository.full_name`, not `repository.owner.login`/`organization.login`), or, after verifying, re-check that `repository.owner.login` matches the owner segment of `repository.full_name` before dispatching to handlers. Alternatively, key incoming webhooks by a URL/path segment identifying the expected organization (e.g. `/webhooks/:organization`) instead of trusting an unauthenticated body field to select which secret validates that same body.

### Proof of Concept
1. Deploy Shipit configured with two GitHub organizations, `orgA` and `orgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org config) [4](#0-3) .
2. Attacker legitimately controls `orgA`'s GitHub App and therefore knows `orgA`'s `webhook_secret`.
3. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha already present in orgB/victim-repo>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature` as `sha1=HMAC-SHA1(orgA_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner = "orgA"`, loads `orgA`'s app, and validates the signature successfully [7](#0-6) .
6. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("orgB/victim-repo")` (from `repository.full_name`) and calls `stack.sync_github(expected_head_sha: params.after)` for `orgB`'s stack [8](#0-7) [1](#0-0) , causing Shipit to sync/deploy `orgB`'s repository using only `orgA`'s webhook secret.

### Citations

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

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class CheckSuiteHandler < Handler
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
      end
    end
  end
end
```
