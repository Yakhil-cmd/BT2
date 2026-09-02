### Title
Signature-verifying org can differ from the repository-owning org in `POST /webhooks`, enabling cross-tenant push forgery — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` derives the GitHub App/org used for HMAC verification solely from `repository.owner.login` in the untrusted JSON body, while `Shipit::Webhooks::Handlers::Handler#stacks` resolves the actual mutated `Repository`/`Stack` from the independent `repository.full_name` field. Because these two attacker-controlled fields are never cross-checked, and because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org has no `webhook_secret` configured, an attacker can name a no-secret org to pass verification while pointing `repository.full_name` at any other org's real repository.

### Finding Description
The invariant that should hold is: `organization_that_verified_signature == organization_that_owns_repository_being_mutated`, i.e. `repository_owner (used in verify_signature) == Repository.from_github_repo_name(repository.full_name).owner (used in Handler#stacks)`.

Trace:
- `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` reads `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the org's config has no `webhook_secret`: `return true unless webhook_secret` [3](#0-2) .
- Once `create` runs, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the same raw body to `PushHandler` [4](#0-3) .
- `Handler#stacks` resolves the target repository from a **different** JSON field, `payload.dig('repository', 'full_name')`, via `Repository.from_github_repo_name` [5](#0-4) [6](#0-5) .
- `PushHandler#process` then syncs every non-archived stack on the attacker-supplied branch and calls `stack.sync_github(expected_head_sha: params.after)` [7](#0-6) .

Nothing in this path checks that `repository.owner.login` matches the owner segment of `repository.full_name`. An attacker crafts a body where `repository.owner.login = "no-secret-org"` (an org configured in `Shipit.github_organizations` but without a `webhook_secret`) and `repository.full_name = "victim-org/victim-repo"` (an org/repo that does exist as a `Shipit::Repository` with active stacks). `verify_signature` resolves `Shipit.github(organization: "no-secret-org")`, finds no secret, and accepts the request unconditionally — the `X-Hub-Signature` header content is irrelevant. The handler then mutates `victim-org/victim-repo`'s stacks.

Existing guards do not stop this: `drop_unhandled_event` only checks the event name is registered [8](#0-7) ; `ExplicitParameters` in `PushHandler` only validates presence of `ref`/`after`, not repository identity [9](#0-8) ; `Repository` validations only constrain character format, not cross-field consistency with the payload's owner field [10](#0-9) .

### Impact Explanation
An unauthenticated attacker can forge a `push` webhook that Shipit accepts as authentic and dispatches against an arbitrary victim organization's repository/stack, as long as (a) some org configured in Shipit lacks a `webhook_secret`, and (b) the victim repository/stack already exists in Shipit. The handler runs `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack matching the forged branch, which can append/advance commits and drive downstream continuous delivery for a repository the attacker never authenticated against. This is a cross-tenant/cross-repository state manipulation via signature bypass — Critical severity per the stated impact categories.

### Likelihood Explanation
Requires that at least one org in the Shipit deployment's GitHub App configuration has no `webhook_secret` set (a realistic and common misconfiguration, e.g. a legacy/staging org or one onboarded without secret rotation) and that the target victim repository is already registered in Shipit with active stacks. Given that precondition, exploitation costs nothing beyond a single crafted HTTP POST with an arbitrary/garbage `X-Hub-Signature` header — no GitHub account, no Shipit session, and no secret material are needed. It is fully repeatable against any repository/branch combination known to the attacker.

### Recommendation
In `WebhooksController#verify_signature`, derive the verifying organization from the same field the handlers use to locate the repository (`repository.full_name`'s owner segment) rather than the independent `repository.owner.login`/`organization.login` fields, and additionally assert that both fields agree before accepting the payload. Also consider removing or gating the `return true unless webhook_secret` fallback in `GitHubApp#verify_webhook_signature` so that orgs without a configured secret cannot silently authenticate arbitrary payloads.

### Proof of Concept
Minitest plan (integration test, no live GitHub):
1. Configure two orgs in `Shipit.github_organizations`/secrets: `"no-secret-org"` with `webhook_secret: nil`, and `"victim-org"` with a real secret.
2. Create `Shipit::Repository.create!(owner: "victim-org", name: "victim-repo")` and an active, non-archived `Shipit::Stack` on branch `"master"` under it.
3. POST to `/webhooks` with header `X-Github-Event: push` and an arbitrary/garbage `X-Hub-Signature` value, and JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "deadbeef...",
     "repository": { "owner": { "login": "no-secret-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
4. Assert both sides of the equality: `repository_owner` (== `"no-secret-org"`, used for verification) is NOT EQUAL to `Repository.from_github_repo_name("victim-org/victim-repo").owner` (== `"victim-org"`, the org actually mutated).
5. Assert the response is `200 OK` (not `422`), and assert that `Stack#sync_github` was invoked (e.g., via mock/spy on the victim stack, or by asserting a resulting commit/state change on the victim stack) — proving a payload verified under one org's identity mutated a different org's stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L41-45)
```ruby
    validates :name, uniqueness: { scope: %i[owner], case_sensitive: false,
                                   message: 'cannot be used more than once' }
    validates :owner, :name, presence: true, ascii_only: true
    validates :owner, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: OWNER_MAX_SIZE }
    validates :name, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: NAME_MAX_SIZE }
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-10)
```ruby
        params do
          requires :ref
          requires :after
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
