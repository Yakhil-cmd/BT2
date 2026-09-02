### Title
Webhook signature verification is keyed by an attacker-controlled `repository.owner.login` while handlers act on the untrusted `repository.full_name` from the same payload, enabling cross-organization writes when any configured org has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks which GitHub App (and therefore which `webhook_secret`) to validate an inbound webhook against based on `repository_owner`, a value read straight out of the untrusted JSON body. Every webhook handler, however, resolves the `Repository`/`Stack` to act on using a *different* field of the same untrusted body: `repository.full_name`. These two fields are never checked against each other, so the "organization that authenticated" and "the repository that is written" are not bound together — exactly the assignment-vs-comparison class of bug described in the report (a check that is supposed to bind two values together silently accepts unrelated ones).

### Finding Description
`verify_signature` derives the organization used for verification purely from the payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the per-organization config and builds a `GitHubApp` for whichever org name is present in the payload: [3](#0-2) 

Signature verification itself is a no-op when that organization has no `webhook_secret` configured — a state that is explicitly documented as optional/nilable in every secrets template in the repo: [4](#0-3) [5](#0-4) 

Meanwhile, every handler that actually mutates state resolves the target `Repository`/`Stack` using `repository.full_name`, a completely different field from the same JSON body: [6](#0-5) [7](#0-6) 

Nowhere in the request pipeline is `repository.owner.login` (used to select the verifying secret) compared against `repository.full_name`'s owner (used to select the object being written). The equality that should hold — "the organization whose secret authenticated this payload" == "the organization owning the repository/stack that the payload's handler will mutate" — is never enforced.

### Impact Explanation
In any multi-tenant Shipit deployment (`config/secrets.yml` keyed by multiple GitHub organizations, as documented in `docs/setup.md` "Using Multiple Github Applications"), if even one configured organization has `webhook_secret` left blank (explicitly shown as a valid/optional state in every secrets template: `webhook_secret: # nil`), an attacker can:

1. Send a POST to `/webhooks` with `X-Github-Event` set to any handled event (`push`, `status`, `check_suite`, `pull_request`, `membership`, ...).
2. Set `repository.owner.login` (or `organization.login`) to the name of the org with no `webhook_secret`. `verify_signature` will call `Shipit.github(organization: <that org>)`, whose `verify_webhook_signature` unconditionally returns `true` because `webhook_secret` is blank.
3. Set `repository.full_name` inside the same payload to any repository belonging to a *different*, secured organization that is tracked by Shipit.
4. The corresponding handler (e.g. `PushHandler`) resolves `Repository.from_github_repo_name(repository.full_name)` and acts on that repository's stacks — with no relationship required between step 2's org and the org actually written to.

This crosses the trust boundary the rules call out ("an organization that authenticated versus the repository that is written") and yields cross-repository writes without any credential: triggering `GithubSyncJob`/`sync_github` on arbitrary tracked stacks, forging commit statuses via `StatusHandler` on arbitrary commits (which feed into deployability/merge-queue decisions), or driving PR-based review-stack archive/unarchive/merge flows on stacks owned by organizations the attacker has no relationship to.

### Likelihood Explanation
Requires no secret, session, or GitHub App credential — only that the deployment has more than one configured GitHub organization and at least one of them has no `webhook_secret` set. This is a state the project's own configuration templates and docs treat as normal/optional (`webhook_secret` marked "(optional)" in `docs/setup.md`, and shown as `# nil` in `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`), making it a realistic operational configuration rather than a contrived edge case.

### Recommendation
Bind the verified organization to the repository being acted upon: after `verify_signature` succeeds, assert that `repository_owner` matches the owner segment of `repository.full_name` (and of `organization.login` for org-scoped events) before dispatching to handlers, rejecting the request otherwise. Additionally, do not treat a missing `webhook_secret` as "verification passes"; require every configured organization in a multi-org deployment to have a secret, or fail closed when a secret is absent.

### Proof of Concept
Given a `config/secrets.yml` such as:
```yaml
production:
  github:
    unsecured-org:
      app_id: 1
      installation_id: 1
      webhook_secret: # left blank
      private_key: ...
    victim-org:
      app_id: 2
      installation_id: 2
      webhook_secret: some-real-secret
      private_key: ...
```
An attacker sends, with no `X-Hub-Signature` header (or any arbitrary value):
```
POST /webhooks
X-Github-Event: push

{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "victim-org/some-tracked-repo"
  }
}
```
`verify_signature` calls `Shipit.github(organization: "unsecured-org")`, whose `verify_webhook_signature` returns `true` unconditionally (blank secret), per [8](#0-7) . `PushHandler` then resolves `Repository.from_github_repo_name("victim-org/some-tracked-repo")` per [9](#0-8)  and calls `stack.sync_github(expected_head_sha: "deadbeef")` on stacks the attacker never authenticated against.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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
