### Title
Webhook signature check authenticates a different organization than the one whose repository the event handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App configuration (and therefore the `webhook_secret` used for HMAC validation) using `repository.owner.login` (or `organization.login`) pulled from the *same unauthenticated JSON body* it is about to validate. Once the signature check passes, the actual event handlers (`Shipit::Webhooks::Handlers::Handler#repository_name`) locate the target `Repository`/`Stack` using a *different* field from that body: `repository.full_name`. Nothing ties these two fields together, so the organization whose secret authenticated the request is not necessarily the organization whose repository/stack is mutated.

### Finding Description
`verify_signature` resolves the app config purely from attacker-controlled payload content: [1](#0-0) [2](#0-1) 

`Shipit::GithubApp#verify_webhook_signature` explicitly treats a blank `webhook_secret` as automatic success: [3](#0-2) 

Shipit's documented "Using Multiple GitHub Applications" setup allows per-organization configs, and its own sample secrets files show `webhook_secret` left blank/nil as a normal, supported state: [4](#0-3) [5](#0-4) 

After the signature gate, every webhook handler resolves the *target* repository/stack from a completely different, unauthenticated field of the same body — `repository.full_name` — with no cross-check against the organization used to select the verifying secret: [6](#0-5) [7](#0-6) 

Binding broken, stated as an equality that the code assumes but never enforces:
`organization_that_authenticated (repository.owner.login used in verify_signature) == organization_whose_repository_is_written (repository.full_name used in Handler#repository_name)`

Before attack: for a genuine GitHub delivery, both fields naturally refer to the same repository, so the equality happens to hold incidentally, not because it's checked.
After attack: an unprivileged network attacker (no `webhook_secret`, no `ApiClient` token, no repo write access) crafts an arbitrary JSON body where `repository.owner.login` (or `organization.login`) is set to any GitHub organization configured in this Shipit instance *without* a `webhook_secret` (a state the project's own docs/config samples treat as valid), while `repository.full_name` is set to any other organization/repository that *does* have a Stack tracked by Shipit. `verify_webhook_signature` short-circuits to `true` because the resolved app's `webhook_secret` is blank, and the handler then acts on the victim repository named in `repository.full_name` — a field never covered by any signature check.

### Impact Explanation
This lets an unauthenticated attacker forge GitHub events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) against any repository/stack tracked by the Shipit instance, as long as one configured GitHub org has no `webhook_secret`. Concretely: a forged `push` event drives `PushHandler#process` to call `stack.sync_github(expected_head_sha: ...)` on the victim's stack, and a forged `status` event lets the attacker fabricate arbitrary commit statuses via `Commit#create_status_from_github!`. In deployments that gate deploys on commit status/CI checks, this can enable an unauthorized deploy by falsifying the checks that unlock the "ship" button — matching the required "unauthorized deploy" impact bar. It also lets an attacker create fake Teams/Users via the `membership` handler and manipulate review-stack lifecycle events.

### Likelihood Explanation
Requires only that the Shipit instance be configured with more than one GitHub organization (a documented, first-class feature) where at least one configured org lacks a `webhook_secret` — a state the project's own documentation and sample secrets files present as acceptable/expected. No credentials, tokens, or GitHub write access are needed; the attacker only needs network reachability to the public `/github_authentication`-adjacent webhooks endpoint and knowledge of the org name lacking a secret (discoverable from public GitHub org pages) and the victim repository's `full_name`.

### Recommendation
Do not select the verifying secret from unauthenticated payload content and separately trust a different unauthenticated field for authorization. Concretely: after resolving the candidate app config from `repository_owner`, verify that the signature was computed with a **non-blank** secret for every organization Shipit is configured to receive events from, i.e. reject events where `webhook_secret` is unset instead of treating it as auto-valid; and additionally assert that `repository.full_name`'s owner segment matches the `repository_owner`/`organization.login` used to select the verifying app before dispatching to handlers, so the two never diverge.

### Proof of Concept
1. Configure Shipit with two GitHub orgs in `secrets.yml`: `OrgA` (no `webhook_secret` set) and `OrgB` (has a Stack tracked, e.g. `OrgB/victim-repo`).
2. As an anonymous attacker, POST to the webhooks endpoint:
```
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000   (any value)

{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` (app/controllers/shipit/webhooks_controller.rb:24-30; lib/shipit/github_app.rb:76-83) regardless of the bogus `X-Hub-Signature`.
4. `PushHandler#process` resolves the target stack via `Repository.from_github_repo_name("OrgB/victim-repo")` (app/models/shipit/webhooks/handlers/handler.rb:33-38) and triggers `sync_github` on `OrgB`'s stack, despite the request never being authenticated by `OrgB`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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
