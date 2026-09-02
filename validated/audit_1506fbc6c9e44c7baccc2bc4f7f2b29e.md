### Title
Webhook signature is verified against the org derived from `repository.owner.login`/`organization.login`, while stack lookup uses the unrelated `repository.full_name` field from the same untrusted payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` used to validate `X-Hub-Signature` based on `repository_owner`, a value read straight out of the attacker-supplied JSON body (`repository.owner.login` or `organization.login`). [1](#0-0) [2](#0-1)  The signature itself only proves the raw body was HMAC-signed with *that* organization's secret; it says nothing about which repository the handlers act on. Handlers, however, resolve the target `Repository`/`Stack` from a different field in the very same body: `repository.full_name`. [3](#0-2)  `Repository.from_github_repo_name` splits that string on `/` and does a plain `find_by(owner:, name:)` lookup with no cross-check against `repository.owner.login`. [4](#0-3) 

### Finding Description
In a multi-organization deployment (`Shipit.github_organizations` / per-org `webhook_secret`s, as documented for "Using Multiple Github Applications" [5](#0-4) ), an attacker who legitimately controls a GitHub App installation on their **own** organization (`attacker-org`) knows that organization's `webhook_secret`. That attacker is fully able to compute a valid `X-Hub-Signature` for an arbitrary body, then POST directly to `/webhooks` (this endpoint has no other authentication - `verify_authenticity_token` is skipped and the only gate is the signature check). [6](#0-5) 

The binding that should hold is:
`organization whose secret authenticated the signature == organization that owns the repository the handler mutates`

but the engine actually enforces:
`organization named in payload.repository.owner.login (used to pick the secret) == organization named in payload.repository.owner.login`
while independently trusting
`payload.repository.full_name (used to pick the Stack/Repository to act on)`

Because `repository.owner.login` and `repository.full_name` are two independent, attacker-controlled strings in the same JSON body, and the code never checks that `full_name` is prefixed by `owner.login`, the attacker can send:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
signed with `attacker-org`'s known `webhook_secret`. `verify_signature` picks `Shipit.github(organization: "attacker-org")` [1](#0-0)  and the signature check passes because the attacker legitimately knows that secret. `verify_webhook_signature` itself only checks the HMAC against `message` (the raw body), it has no notion of which org the body claims to be about. [7](#0-6)  Once past that gate, `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack with that branch. [8](#0-7)  `sync_github` enqueues `GithubSyncJob`, which fetches/updates commits for the target repository/branch using Shipit's own GitHub credentials, effectively letting the attacker drive Shipit's view of `victim-org/victim-repo`'s HEAD and trigger downstream sync/deploy behavior for a repository the attacker does not control, without ever presenting `victim-org`'s real webhook secret.

The same pattern applies to every other handler that also derives `Repository` from `params.repository.full_name` (opened/closed/labeled/unlabeled/reopened/edited pull-request handlers, `Handler#stacks`), all of which inherit the same disconnect between "org that signed" and "repo that gets written to." [3](#0-2) 

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" binding explicitly called out as in-scope. An attacker who only controls a GitHub App/webhook installed on an organization they own can force Shipit to process forged push/PR events for a `Stack` belonging to a different organization present on the same Shipit instance, triggering unauthorized `GithubSyncJob` syncs (and consequently deploy-eligible commit ingestion) against that victim stack. This qualifies as an unauthorized action against a stack the attacker's credentials do not authorize, satisfying the High-impact bar (escalation of what the attacker's authenticated org boundary should permit).

### Likelihood Explanation
Requires a multi-organization Shipit deployment where the attacker legitimately owns/administers at least one of the configured GitHub organizations (a realistic scenario for shared internal Shipit instances serving multiple teams/orgs). No repository write access, session, or `ApiClient` token is needed - only knowledge of a webhook secret the attacker is entitled to (their own org's), and the ability to POST directly to the public `/webhooks` endpoint.

### Recommendation
After signature verification, cross-check that `repository.full_name`'s owner segment matches `repository_owner` (the org whose secret verified the signature) before resolving stacks/handlers; reject the webhook otherwise instead of trusting `full_name` independently.

### Proof of Concept
1. Configure Shipit in multi-org mode with `attacker-org` and `victim-org` each having their own `webhook_secret` (per `docs/setup.md` "Using Multiple Github Applications").
2. Attacker computes `sha1=HMAC-SHA1(attacker-org's webhook_secret, raw_body)` for:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. POST to `/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates successfully. [1](#0-0) 
5. `PushHandler` looks up stacks for `victim-org/victim-repo` and calls `sync_github` on them, even though the request was never signed with `victim-org`'s secret. [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
