### Title
Webhook signature verification keys off `repository.owner.login` while all event handlers dispatch on `repository.full_name` — cross-organization forgery of webhook events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) inside the request body itself, but every webhook handler resolves the target `Repository`/`Stack` using a *different* field of the same body: `repository.full_name`. These two fields are never checked against each other, so an attacker who legitimately possesses the `webhook_secret` for one configured organization can forge a signed payload whose `repository.owner.login` matches that organization (to pass signature verification) while `repository.full_name` points at a Stack belonging to an entirely different organization configured in the same Shipit instance.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and uses it purely to pick the secret for HMAC verification: [1](#0-0) [2](#0-1) 

The signature is verified with `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, and `GitHubApp#verify_webhook_signature` uses a per-organization `webhook_secret` from `secrets.yml`: [3](#0-2) 

Deployments support multiple orgs, each with its own secret: [4](#0-3) 

However, once the signature passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *entire raw payload* to handlers, and the base `Handler` class resolves the target stacks using `repository.full_name`, an entirely separate field from the one used to choose the verification secret: [5](#0-4) [6](#0-5) 

Because the HMAC is computed over the raw JSON body, the signature itself does bind `full_name` cryptographically to the *secret used*, but it does not bind `full_name` to `owner.login` — nothing in `verify_signature` or in the handlers cross-checks that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login`. This breaks the intended equality: `organization whose secret authenticated the delivery == organization owning the repository actually acted upon`. Anyone administering the GitHub App/webhook configuration for *any one* of the organizations hosted by a shared Shipit instance (i.e., the entity that created that GitHub App and knows its `webhook_secret` — not a Shipit user, not an `ApiClient`, not a privileged Shipit account) can send a POST to `/github/webhooks` (or wherever the engine mounts `WebhooksController`) with:
- `repository.owner.login` = their own organization (so `verify_signature` picks their own secret and the HMAC matches)
- `repository.full_name` = `"other-org/other-repo"` (or `organization.login` for the `membership` event) to target any Stack configured in the shared Shipit instance

This lets the attacker drive any handler (`push_handler.rb`, `status_handler.rb`, `check_suite_handler.rb`, `pull_request/*_handler.rb`, `membership_handler.rb`) against a repository/organization they do not control.

### Impact Explanation
This crosses a repository-write / cross-organization boundary explicitly called out in scope: "an organization that authenticated versus the repository that is written." Concretely reachable abuses include:
- Forging `status` events (`status_handler.rb`, reached via `Handler#stacks`) to mark arbitrary commits on a victim org's stack as CI-green, which is exactly the kind of gate Shipit checks before allowing an "unauthorized deploy" (`ci.require` in `shipit.yml`).
- Forging `push` events (`push_handler.rb`) to trigger `GithubSyncJob` against a victim stack with attacker-chosen `after` SHA, injecting fabricated commit records into a repository Shipit believes to be legitimate.
- Forging `pull_request` events (`opened_handler.rb`, `closed_handler.rb`, `labeled_handler.rb`) against victim ReviewStacks/merge-queue logic tied to a different org's repository.

Since this can feed false CI/status data or fabricated push history into a victim organization's stack — potentially enabling an unauthorized deploy decision — this satisfies the required Critical/High impact bar ("unauthorized deploy" / cross-repository writes).

### Likelihood Explanation
Requires only knowledge of a `webhook_secret` for *any one* organization hosted on a shared Shipit deployment (a value the organization's own GitHub App administrator possesses by design — not a Shipit credential, Shipit session, or `ApiClient` token). This is realistic in any Shipit deployment serving multiple organizations/teams (as explicitly supported by `secrets.*.yml` structure with multiple named orgs), where trust boundaries between the tenant organizations are expected to be enforced by Shipit itself, not by mutual trust between tenants.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after verifying the signature, enforce that the organization used to select the `webhook_secret` (`repository_owner`) matches the owner segment of `repository.full_name` (and `organization.login` for org-scoped events like `membership`) before dispatching to handlers. Reject the request (e.g., `head(422)`) on mismatch.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own `webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. As an entity that knows only `orgA`'s `webhook_secret` (e.g., the GitHub App admin for `orgA`), construct a `status` (or `push`) webhook JSON body where:
   - `repository.owner.login = "orgA"`
   - `repository.full_name = "orgB/victim-repo"`, `sha` = a commit on an `orgB` stack, `state = "success"`, `context` = one of the `ci.require` contexts for that stack.
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>` and POST to the webhooks endpoint with `X-Github-Event: status`.
4. `verify_signature` picks `Shipit.github(organization: "orgA")`, verifies successfully against `orgA`'s secret.
5. `Shipit::Webhooks.for_event('status')` handler resolves stacks via `Repository.from_github_repo_name("orgB/victim-repo")` and creates a fabricated green `Status` for `orgB`'s stack/commit — despite the attacker having no relationship to `orgB` or its webhook secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
