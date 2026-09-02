### Title
Webhook signature verified against `repository.owner.login`'s org secret while `Handlers::Handler` resolves the target Stack from the same payload's unchecked `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC against using `params.dig('repository','owner','login')`, but the payload is attacker-controlled JSON and this field is never cross-checked against the `repository.full_name` field that `Shipit::Webhooks::Handlers::Handler#repository_name` later uses to look up the target `Repository`/`Stack`. An attacker who can produce a valid signature for org A's `webhook_secret` (per the question's stated precondition) can submit a body where `repository.owner.login == "A"` (used only for signature selection) while `repository.full_name == "B/repo"` (used to load and mutate org B's `Stack`).

### Finding Description
The claimed binding is: `signing_organization(payload) == target_organization(payload)`, i.e. the org whose secret validated the HMAC must equal the org that owns the `Repository`/`Stack` being mutated.

Tracing the code:
- `WebhooksController#verify_signature` computes `repository_owner` purely from the unauthenticated body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and uses it to pick the GitHub App config/secret: `github_app = Shipit.github(organization: repository_owner)` then verifies `X-Hub-Signature` against `request.raw_post` with that org's secret [2](#0-1) .
- Once verified, `create` parses the same raw body and dispatches it unchanged to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .
- `Handler#stacks` (used by `PushHandler`) and every PR handler resolve the target repository from a *different* field of the same payload: `payload.dig('repository', 'full_name')` [4](#0-3) , feeding `Repository.from_github_repo_name`, which just splits on `/` and does a DB lookup with no relation to the org that signed the request: `repo_owner, repo_name = github_repo_name.downcase.split('/'); find_by(owner: repo_owner, name: repo_name)` [5](#0-4) .
- `PushHandler#process` then mutates matched stacks: `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }` [6](#0-5) . PR handlers (`opened`, `closed`, `labeled`, etc.) similarly resolve `repository` via `params.repository.full_name` and archive/unarchive/create review stacks, all independent of `repository_owner` used at signature time [7](#0-6) .

Nowhere is `repository.owner.login` compared against the owner segment of `repository.full_name`. The `ExplicitParameters` schemas only require the field types/presence (`requires :repository do requires :full_name, String end`), never their mutual consistency, and `drop_unhandled_event`/`check_if_ping` do not touch this either. Consequently, given the question's stated precondition that an attacker can produce a valid HMAC for org A's `webhook_secret` over an arbitrary body (e.g., because org A's webhook secret is compromised/knowable to them or because signature verification is bypassable for that org — the question's stated proof condition), they can set `repository.owner.login = "A"` and `repository.full_name = "B/repo"` in the same forged body and have `verify_signature` pass while `PushHandler`/PR handlers mutate org B's `Stack`.

### Impact Explanation
If the precondition holds (attacker can compute a valid signature for org A but chooses an arbitrary `full_name`), the request causes writes against `Stack`/`Commit`/`PullRequest`/review-stack records that belong to an entirely different organization (B) than the one whose secret validated the request. This is a cross-tenant write: `Stack#sync_github` enqueues `GithubSyncJob` for B's stack, and PR handlers can archive/unarchive/create B's review stacks. Because the write targets are chosen entirely by attacker-supplied `full_name` in the request body, the attack is repeatable against any repository/stack Shipit tracks for org B, not limited to one target. This matches the "Critical — a payload for one repository mutating another's stack/commit/task" category.

### Likelihood Explanation
Exploitation strictly requires the precondition stated in the question: the attacker must already be able to produce a valid `X-Hub-Signature` for some org A's configured `webhook_secret` over an arbitrary body. Nothing in this engine's own code (`verify_webhook_signature` in `lib/shipit/github_app.rb`) restricts what content can be signed — it HMACs `request.raw_post` verbatim, so once a valid signature for *any* body is obtainable, the code path described above imposes no further correlation checks between the signing org and the target org. The engine-side gap (missing cross-check between `repository.owner.login` and `repository.full_name`) is unconditional and always present; the overall likelihood of full exploitation is gated by how the attacker obtains a valid signature for org A, which is outside this engine's code but assumed true by the question.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), enforce that the organization used to select/verify the webhook secret matches the owner segment of `repository.full_name` (and `organization.login` for org-level events) before dispatching to handlers — e.g. reject the request if `repository.full_name.split('/').first.casecmp(repository_owner) != 0`. Alternatively, resolve `Shipit.github(organization:)` and the target `Repository` from the same single trusted field, and derive `repository_owner` from that resolved `Repository#owner` rather than trusting a second independent JSON field.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "signature valid for org A's secret does not let full_name=B/repo mutate org B's stack" do
  # Org A ("shopify") webhook_secret is used to sign; org B stack ("cyclimse/cyclimse", fixture-dependent) is the real target.
  org_a_secret = Shipit.github(organization: 'shopify').webhook_secret
  target_stack = shipit_stacks(:cyclimse) # belongs to a different owner/org than "shopify"

  forged_payload = JSON.parse(payload(:push_master))
  forged_payload['repository']['owner']['login'] = 'shopify'          # org A -> used for signature org lookup
  forged_payload['repository']['full_name']       = target_stack.repository.github_repo_name # org B's real repo
  forged_payload['ref'] = "refs/heads/#{target_stack.branch}"
  body = forged_payload.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', org_a_secret, body)

  @request.headers['X-Github-Event'] = 'push'
  @request.headers['X-Hub-Signature'] = signature

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: target_stack.id, expected_head_sha: forged_payload['after']]) do
    post :create, body:, as: :json
  end

  assert_response :ok # signature accepted under org "shopify" even though full_name targets a different org's stack
end
```
This asserts both sides of the binding explicitly: the signature is verified using org A's (`shopify`) `webhook_secret`, yet `GithubSyncJob` is enqueued for `target_stack`, which belongs to a different repository owner — demonstrating `signing_organization(payload) != target_organization(payload)` while the request is still processed.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
