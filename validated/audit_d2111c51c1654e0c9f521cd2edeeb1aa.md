### Title
Webhook organization used for signature verification is decoupled from the repository the payload is allowed to mutate - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to authenticate a webhook against using `repository_owner`, a value read directly from the *unverified* JSON body (`repository.owner.login` or `organization.login`). Once verification "passes," every registered handler (`PushHandler`, `PullRequest::*Handler`, `StatusHandler`, `CheckSuiteHandler`, …) independently re-reads the same body and resolves the target `Repository`/`Stack` from a *different* field, `repository.full_name`, with no requirement that this repository actually belongs to the organization whose secret validated the request.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) [2](#0-1) 

`repository_owner` is used only to pick which configured `GitHubApp` performs the HMAC check: [3](#0-2) 

`GitHubApp#verify_webhook_signature` explicitly no-ops when the selected org has no `webhook_secret` configured: [4](#0-3) 

`webhook_secret` is documented and shipped as optional in every example/dummy config in this engine, including the multi-org case: [5](#0-4) [6](#0-5) 

Once `verify_signature` passes (trivially, for any organization with no secret configured), `create` dispatches the raw, unverified body to handlers: [7](#0-6) 

Every handler resolves its target `Repository`/`Stack` from `repository.full_name`, a field that is never cross-checked against `repository_owner`: [8](#0-7) [9](#0-8) 

The broken equality is:
`organization used to select/pass the signature check (payload.repository.owner.login)` **must equal** `organization owning the repository actually mutated (payload.repository.full_name's owner segment)` — but the engine never enforces this.

### Impact Explanation
In any deployment using the documented multi-organization config (`docs/setup.md`'s "Using Multiple Github Applications" section, or Shopify's own `secrets.development.shopify.yml`/`secrets_double_github_app.yml` examples, all of which ship `webhook_secret: # nil`), an unauthenticated attacker can:

1. POST to `/webhooks` with `X-Github-Event: push` and body `{"repository": {"owner": {"login": "<org-with-no-secret>"}, "full_name": "<victim-org>/<victim-repo>"}, "ref": "refs/heads/<branch>", "after": "<sha>"}`.
2. `verify_signature` resolves `Shipit.github(organization: "<org-with-no-secret>")`, whose `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank — no valid `X-Hub-Signature` is required at all.
3. `PushHandler` then looks up the real `Repository`/`Stack` for `<victim-org>/<victim-repo>` (a completely different, properly-secured organization) and calls `stack.sync_github(expected_head_sha: params.after)`, which — for continuous-deployment stacks — can trigger an unauthorized sync/deploy cycle on a stack the attacker has no relationship to.

This constitutes an unauthorized deploy trigger through a credential/organization-binding bypass, satisfying the High/Critical "unauthorized deploy" impact bar without any Shipit session, API token, or knowledge of any real `webhook_secret`.

### Likelihood Explanation
Any Shipit deployment following the engine's own documented "Using Multiple Github Applications" pattern, or simply leaving the optional `webhook_secret` unset for any one configured organization (as every checked-in example config in this repository does), is exposed. The attacker needs no credentials, no repository access, and no knowledge of any secret — only the target's public `owner/repo` full name and branch, both of which are typically public knowledge for any Shipit-tracked stack.

### Recommendation
Enforce that the organization used to select/verify the webhook signature is the same organization that owns the repository the payload is allowed to act on: derive `repository_owner` strictly from `payload.dig('repository', 'full_name')`'s owner segment (not from `repository.owner.login`/`organization.login`, which duplicate but aren't required to match), and additionally reject any webhook when the resolved `GitHubApp` has no `webhook_secret` configured rather than treating an absent secret as "verified." At minimum, hard-fail (rather than pass-through) when `webhook_secret` is blank, and add a check in each handler that the repository resolved from the payload belongs to the same organization that validated the signature.

### Proof of Concept
Given a Shipit instance configured with `OrgA` (no `webhook_secret`) and `OrgB` (secret set, tracks `OrgB/prod-app` with continuous deployment enabled):

```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/prod-app"},
  "ref": "refs/heads/master",
  "after": "<known-good-sha-for-OrgB/prod-app>"
}
```

`verify_signature` selects the `OrgA` `GitHubApp` (`Shipit.github(organization: "OrgA")`), whose `verify_webhook_signature` returns `true` unconditionally because `OrgA.webhook_secret` is `nil` — the request is accepted with no valid signature. `PushHandler#process` then resolves `Repository.from_github_repo_name("OrgB/prod-app")` and enqueues a sync/deploy for `OrgB`'s stack, even though the signature check was never actually performed against `OrgB`'s secret.

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

**File:** docs/setup.md (L182-209)
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
