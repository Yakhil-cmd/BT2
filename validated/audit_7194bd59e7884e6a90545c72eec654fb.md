### Title
Webhook signature verification authenticates the wrong field — the "authenticating organization" and the "repository acted upon" are unbound (`app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which per-organization `GitHubApp`/secret to use for HMAC verification based on `repository_owner`, a value read straight out of the untrusted JSON body (`repository.owner.login` or `organization.login`). Every webhook handler, however, decides *which repository/stack to act on* using a different field of the same body — `payload.dig('repository', 'full_name')`. Nothing binds these two fields together, and Shipit explicitly supports per-organization configs where `webhook_secret` is `nil` (verification then trivially returns `true`). An attacker who can get a signature accepted for any one configured organization (including a deliberately/accidentally secret-less one) can point `repository.full_name` at a completely unrelated organization's repository/stack and have Shipit's handlers act on it.

### Finding Description
`verify_signature` picks the app config purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

The actual signature check in `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever that organization's `webhook_secret` is blank — a state the codebase treats as a supported configuration, not an error: [3](#0-2) [4](#0-3) 

`Shipit.github` resolves the app purely by the organization key given, with multi-org support built in: [5](#0-4) 

Once `verify_signature` passes, the controller dispatches the entire raw payload to every handler for the event, without any re-validation that the "authenticated" organization matches the repository the handler will operate on: [6](#0-5) 

Every handler independently derives its target repository/stack from `payload.dig('repository', 'full_name')` — a field completely disjoint from the `repository_owner` value that drove signature verification: [7](#0-6) [8](#0-7) 

This is the same class of bug as the reported Rust issue: a value used to satisfy a guard/check (`num_txs` decrement in the report; here, the "authenticated organization") diverges from the value the actual operation is keyed on (the real transaction count; here, `repository.full_name`, i.e. the repository actually written to). The equality that should hold — `organization_used_for_signature == owner(repository_acted_upon)` — is never enforced.

### Impact Explanation
In any Shipit deployment configured for multiple GitHub organizations (a first-class, documented feature — see `Shipit.github_organizations`, `github_app_config`) where at least one organization has no `webhook_secret` set (an explicitly supported value, as shown in the fixture above), an attacker can:
- Send an unsigned/arbitrarily-signed POST to the shared `/webhooks` endpoint with `X-Github-Event: status` (or `push`), setting `repository.owner.login`/`organization.login` to the secret-less organization, and `repository.full_name` to a repository belonging to a *different*, secured organization that is registered as a Shipit stack.
- `verify_signature` accepts the request because the resolved `GitHubApp` for the spoofed org has no secret.
- `Handlers::StatusHandler` (or `PushHandler`) then acts on the *target* repository named in `repository.full_name`, creating a forged commit `Status` (e.g. `state: success`) or triggering a sync, for a repository entirely outside the attacker's control.

Because commit deployability (`until_commit.deployable?`) is derived from these statuses and gates both manual deploys and `Stack.schedule_continuous_delivery`'s automatic `ContinuousDeliveryJob`, a forged "success" status on an otherwise-blocked/malicious commit can cause an **unauthorized automated deploy** with no human interaction — satisfying the Critical "unauthorized deploy" impact bar.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment, and (2) at least one configured organization with a blank `webhook_secret`. Both are supported, documented configurations rather than engine-mounting deviations — the test fixtures ship exactly this shape (`secrets_double_github_app.yml` with `webhook_secret: # nil`). No GitHub credentials, repository write access, or privileged account are needed once such a config exists; the attacker only needs the public webhook endpoint URL, which is fixed and documented (`/webhooks`). Likelihood is therefore contingent on deployment configuration but requires no credential beyond that.

### Recommendation
Cross-validate that the organization/owner used to select and verify the webhook signature matches the owner of `repository.full_name` (or `organization.login`) that handlers subsequently act on, rejecting mismatches with 422 before dispatching to any handler. Additionally, consider treating a blank/missing `webhook_secret` for a configured organization as a hard misconfiguration (fail closed) rather than an implicit signature bypass.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (no `webhook_secret`) and `OrgB` (secured, and having a registered Shipit stack for `OrgB/victim-repo`) — mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. POST to `/webhooks` with headers `X-Github-Event: status` and no valid `X-Hub-Signature` needed, body:
```json
{
  "sha": "<any commit sha tracked by OrgB/victim-repo>",
  "state": "success",
  "target_url": "https://attacker.example/ok",
  "context": "ci/attacker",
  "description": "forged",
  "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of body/signature.
4. `Shipit::Webhooks::Handlers::StatusHandler` processes the payload using `repository.full_name = "OrgB/victim-repo"`, creating a forged successful `Status` on `OrgB`'s commit, potentially flipping `deployable?` to `true` and enabling continuous-delivery auto-deploy of that commit.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
