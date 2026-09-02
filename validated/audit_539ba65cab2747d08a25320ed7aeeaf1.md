### Title
Cross-tenant stack sync via `repository.owner.login` / `repository.full_name` mismatch in webhook payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook by looking up the GitHub App/secret for `params.dig('repository','owner','login')` (or `organization.login`), while `Handler#stacks`/`Handler#repository_name` resolves the target `Stack` using the independent field `payload.dig('repository','full_name')`. These two fields live in the same attacker-controlled JSON body and are never checked for consistency, letting an attacker who legitimately controls a webhook secret for org A forge a payload that is authenticated as org A but targets org B's stack.

### Finding Description
Broken binding: `repository.owner.login` (used to select the secret for `verify_signature`) must equal the owner encoded in `repository.full_name` (used by `Handler#repository_name`/`Handler#stacks` to resolve the `Stack`). This equality is never enforced.

Code path:
- `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and uses it to fetch the GitHub App/secret: `Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(...)` against the raw body [2](#0-1) .
- On success, `create` parses the full raw body and dispatches it, unmodified, to handlers: `handler.call(params)` [3](#0-2) .
- `Handler#repository_name` reads a *different* field of the same payload: `payload.dig('repository', 'full_name')` [4](#0-3) , and `Handler#stacks` resolves stacks purely from that string via `Repository.from_github_repo_name(repository_name)` [5](#0-4) .
- `Repository.from_github_repo_name` just splits the string on `/` and does a DB lookup with no relation back to who signed the request [6](#0-5) .
- `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on whatever stacks matched, using an attacker-supplied `after` SHA [7](#0-6) .

Exploit: an attacker who owns/administers a real GitHub repo under org A (and therefore has org A's legitimate webhook configured, i.e., a valid `X-Hub-Signature` computable for org A) sends `POST /webhooks` with header `X-Github-Event: push` and a JSON body where `repository.owner.login` = `"orgA"` (or omits it and sets `organization.login` = `"orgA"`) but `repository.full_name` = `"orgB/victim-repo"`, and signs the raw body with org A's real secret. `verify_signature` looks up org A's secret (which the attacker legitimately possesses/controls) and validation succeeds. `Handler#stacks` then resolves `orgB/victim-repo`'s real `Stack` records and `PushHandler#process` invokes `stack.sync_github(expected_head_sha: <attacker-chosen sha>)` against org B's stack — a repository the attacker never authenticated against.

None of the existing guards catch this: `verify_signature` only checks that *some* valid signature exists for whatever owner the attacker names in `owner.login`/`organization.login`; it never compares that owner to the owner embedded in `full_name`. `drop_unhandled_event` and `check_if_ping` are unrelated. There is no `ExplicitParameters` validation constraining `repository.full_name` relative to `repository.owner.login` (the `params` block in `PushHandler` only validates `ref`/`after`) [8](#0-7) . `Repository`/`Stack` model validations only constrain owner/name character sets, not cross-request authorization [9](#0-8) .

### Impact Explanation
An attacker with control over one legitimately configured GitHub org/repo (their own tenant) can force `Stack#sync_github` to run against any other tenant's stack with an attacker-chosen `expected_head_sha`, and this can cascade into whatever `sync_github`/downstream auto-deploy pipeline does for that victim stack. This is a payload-for-one-repository-mutating-another's-stack scenario, matching the Critical impact category. It is repeatable for every push webhook the attacker sends and works against any stack whose owner/name string the attacker can guess or discover (stack names/repos are often public GitHub repo names), so blast radius spans all tenants configured on the same Shipit instance.

### Likelihood Explanation
Preconditions: Shipit must be configured with a valid `webhook_secret`/GitHub App for at least one org that the attacker controls (a normal, legitimate multi-tenant setup), and the victim org/stack must exist on the same Shipit instance. Attacker cost is low — crafting a JSON body with mismatched `repository.owner.login`/`organization.login` vs `repository.full_name` and signing it with their own known secret requires no privileged access, no session, no API token, and no knowledge of the victim's secret. This is fully repeatable and does not require live GitHub interaction to reproduce in tests.

### Recommendation
In `Handler#repository_name`/`Handler#stacks`, do not trust `payload.dig('repository','full_name')` alone; require that the owner segment of `full_name` matches the `repository.owner.login`/`organization.login` value that was used to select and verify the signature (pass the verified `repository_owner` into the handler and assert equality with the owner parsed out of `full_name` before resolving stacks), rejecting/dropping the event otherwise.

### Proof of Concept
Minitest plan (no live GitHub, stub `GithubApp#verify_webhook_signature` to return true for org A's secret):
1. Create `Repository`/`Stack` for org A (`orga/repoa`) and org B (`orgb/repob`), each with distinct configured `webhook_secret`s in `Shipit.github_configs`.
2. Build a push payload: `{ "ref" => "refs/heads/master", "after" => "attackersha", "repository" => { "owner" => { "login" => "orga" }, "full_name" => "orgb/repob" } }`.
3. Compute `X-Hub-Signature` using org A's real secret against the raw JSON body (simulating the attacker, who legitimately has this secret).
4. POST to `/webhooks` with `X-Github-Event: push` and that signature.
5. Assert response is `200 OK` (signature accepted, since `repository_owner` resolves to `"orga"`).
6. Assert/mock that `Stack#sync_github` is invoked on org B's stack (`orgb/repob`) with `expected_head_sha: "attackersha"` — i.e., `stack_b.expects(:sync_github).with(expected_head_sha: "attackersha")`.
7. Equality check both sides: before, `repository_owner` ("orga") == owner used to verify signature ("orga") — true; but `repository_owner` ("orga") != owner embedded in `repository.full_name` ("orgb") — mismatch, proving the missing binding, while the sync is still executed against org B's stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-34)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L36-38)
```ruby
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
