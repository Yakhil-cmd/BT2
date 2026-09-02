### Title
Webhook signature is verified against the org derived from `repository.owner.login`, but the repository actually mutated is taken from the unauthenticated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate the HMAC signature using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (or `organization.login`). However, the actual repository that webhook handlers act on is computed separately in `Shipit::Webhooks::Handlers::Handler#repository_name`, which reads `payload.dig('repository', 'full_name')`. These are two independent, attacker-controlled fields inside the same JSON body. An attacker who controls (or is a legitimate low-privilege member of) any GitHub organization configured in this Shipit instance knows that organization's `webhook_secret`, and can therefore forge a signature that is valid for "their" org while setting `repository.full_name` to point at a completely different repository/stack belonging to another organization.

### Finding Description
`verify_signature` picks the signing app by `repository_owner`: [1](#0-0) 
`repository_owner` itself is just a field pulled out of the untrusted JSON body: [2](#0-1) 

Once the signature check passes, `Handler#stacks` resolves the target repository using a *different* field of the same payload, `repository.full_name`, with no re-check that it belongs to the org that was authenticated: [3](#0-2) 
`Repository.from_github_repo_name` simply splits `owner/name` out of that string and looks the record up directly: [4](#0-3) 

Because `owner.login` (used for signature selection) and `full_name` (used for repository resolution) are never cross-checked, an attacker can craft a payload where:
- `repository.owner.login` = `attacker-org` (whose `webhook_secret` the attacker legitimately knows, e.g. because they administer that org's GitHub App/webhook), and
- `repository.full_name` = `victim-org/victim-repo`

The signature will validate successfully (it's checked against `attacker-org`'s secret), yet the handler will act on `victim-org/victim-repo`'s stacks. This breaks the trust binding "the organization whose signature authenticated the request" ⇔ "the repository the payload is applied to".

Concretely reachable handlers include:
- `PushHandler#process`, which triggers `stack.sync_github(expected_head_sha:)` for any stack matching the branch of the forged `full_name`/`ref`: [5](#0-4) 
- `StatusHandler#process`, which creates a forged commit status on the victim's commit via `commit.create_status_from_github!`: [6](#0-5) 

Commit status directly feeds `deployable?`, which gates whether a commit can be deployed: [7](#0-6) 

### Impact Explanation
An attacker who controls any single organization onboarded onto the Shipit instance (i.e., knows that org's `webhook_secret`) can forge webhook deliveries that are attributed to a victim repository/organization they have no access to. This lets them:
- Inject forged `success` commit statuses on a victim stack's commits, flipping `deployable?` to true and clearing the CI gate that would otherwise block deployment — an unauthorized-deploy enabling primitive.
- Force `GithubSyncJob` to run against a victim stack with an attacker-chosen `expected_head_sha`, causing cross-repository state corruption.

This crosses an authentication boundary between organizations and satisfies the "cross-repository writes" / "unauthorized deploy" Critical impact bar, since it is achieved purely by crafting a webhook payload once *any* org's webhook secret is known (which is a much weaker precondition than repository write access or an `ApiClient` token to the victim's own resources).

### Likelihood Explanation
Requires the attacker to legitimately control/administer at least one GitHub organization already configured on the shared Shipit instance (a realistic multi-tenant scenario, since `Shipit.github(organization:)` supports multiple configured orgs, as seen in `test/dummy/config/secrets_double_github_app.yml`). No access to the victim org or repository is needed — only crafting the JSON body's `repository.full_name` field, since it is completely decoupled from the signature-verification path.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), assert that the organization used to validate the HMAC signature (`repository_owner`) matches the owner segment of `repository.full_name` (and `organization.login` if present) before processing the event. Reject the webhook if they diverge.

### Proof of Concept
1. Attacker administers `attacker-org` on the shared Shipit instance and knows its `webhook_secret`.
2. Attacker sends a `status` webhook to `POST /webhooks` with:
   - Header `X-Hub-Signature` = HMAC-SHA1 of the body using `attacker-org`'s webhook secret.
   - Body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "sha": "<victim commit sha>", "state": "success", ...}`
3. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and validates successfully against the attacker's own known secret. [1](#0-0) 
4. `StatusHandler#process` resolves `Repository.from_github_repo_name('victim-org/victim-repo')` via `full_name` and creates a forged `success` status on the victim's commit, flipping `deployable?` for a stack the attacker has no legitimate access to. [3](#0-2)

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
