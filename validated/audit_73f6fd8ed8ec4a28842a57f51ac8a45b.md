### Title
Webhook signature verification keyed on `repository.owner.login` while write path acts on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate against using `repository.owner.login` (falling back to `organization.login`), while `Shipit::Webhooks::Handlers::Handler#repository_name` — used by every handler (`push`, `status`, `pull_request/*`) to decide which `Repository`/`Stack` record to mutate — reads a *different* JSON field, `repository.full_name`. This is the "organization that authenticated versus the repository that is written" binding called out in scope: the equality `verified_org == acted_on_repository.owner` is never enforced.

### Finding Description
`verify_signature` computes the trust anchor from one field: [1](#0-0) [2](#0-1) 

The signature itself is only ever validated `unless webhook_secret` — for any configured GitHub organization that has no `webhook_secret` set (a documented, supported configuration, see `config/secrets.development.shopify.yml`), `verify_webhook_signature` returns `true` unconditionally regardless of the body or the header: [3](#0-2) 

Meanwhile, every webhook handler determines which repository/stack to write to from a completely independent field of the same attacker-supplied JSON body: [4](#0-3) 

Because `repository.owner.login` (used for auth org selection) and `repository.full_name` (used for the write target) are read from two unrelated locations in the same untrusted, attacker-controlled JSON body, and the endpoint is publicly mounted with no session/API-client requirement (`resources :webhooks, only: :create` in `config/routes.rb`), a POST body can be crafted where these two fields disagree. If any one configured organization on the instance has a blank `webhook_secret` (`verify_webhook_signature` short-circuits to `true`), an attacker can set `repository.owner.login` to that no-secret organization to trivially pass signature verification, while setting `repository.full_name` to point at a totally unrelated organization/repository whose stacks get mutated by the handler (e.g. `PushHandler#process` triggering `stack.sync_github`, or `StatusHandler#process` calling `commit.create_status_from_github!` to inject a synthetic commit status): [5](#0-4) [6](#0-5) 

The webhooks controller never checks that the organization used to authenticate the payload actually owns the repository named in `repository.full_name`, breaking the binding "organization authenticated == repository written."

### Impact Explanation
An attacker who controls no credentials for the target organization can inject arbitrary GitHub commit statuses (`create_status_from_github!`) or trigger repository syncs against stacks belonging to a different, victim organization/repository configured on the same Shipit instance, as long as one other configured organization has no `webhook_secret`. Spoofed commit statuses can satisfy required-status-check gating used to determine deployability, enabling an unauthorized deploy on a repository the attacker never authenticated against — this falls in the Critical "unauthorized deploy" bucket.

### Likelihood Explanation
Requires a multi-tenant Shipit deployment where at least one configured GitHub organization lacks a `webhook_secret` — a state the codebase itself documents and supports (`config/secrets.development.shopify.yml`), not a hypothetical misuse. No credentials, sessions, or API tokens are needed to reach `/webhooks`, so the barrier is purely the operator's configuration choice, which the code silently permits without warning that it removes the org-binding guarantee for all other tenants.

### Recommendation
After signature verification succeeds, verify that the authenticated organization (used to select the webhook secret) matches the `owner` implied by `repository.full_name` (and `organization.login` if present) before dispatching to handlers. Alternatively, require a `webhook_secret` for every configured organization and reject payloads for organizations with no secret rather than treating a missing secret as "always verified."

### Proof of Concept
1. Configure Shipit with two organizations: `victim-org` (has `webhook_secret` set) and `no-secret-org` (no `webhook_secret`, as shown supported in `config/secrets.development.shopify.yml`).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "repository": {
    "owner": { "login": "no-secret-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. `verify_signature` resolves `repository_owner` = `no-secret-org` → `Shipit.github(organization: 'no-secret-org').verify_webhook_signature` returns `true` unconditionally (no secret configured), regardless of the (missing/garbage) `X-Hub-Signature` header.
4. `StatusHandler#process` runs unaffected, looking up commits by `sha` across the whole install (`Commit.where(sha: params.sha)`, in `app/models/shipit/webhooks/handlers/status_handler.rb`), writing a forged `success` status onto a commit belonging to `victim-org/victim-repo`, potentially satisfying deploy-gating checks for that stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
