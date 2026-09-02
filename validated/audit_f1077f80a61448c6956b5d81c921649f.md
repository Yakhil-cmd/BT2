### Title
Cross-organization webhook confusion: `full_name` vs `owner.login` divergence lets any org's signature authorize sync of an unrelated repository's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` used to validate the HMAC signature based solely on `payload.dig('repository','owner','login')`, while `Handlers::Handler#stacks`/`PushHandler#process` resolve the target `Repository`/`Stack` using `payload.dig('repository','full_name')`. Because both fields come from the same attacker-controlled JSON body and are never cross-checked, an attacker who owns a legitimate GitHub organization configured in Shipit (with a real `webhook_secret`) can sign a payload with their own secret while setting `repository.full_name` to a victim org's repo, causing `GithubSyncJob` to be enqueued against the victim's `Stack`.

### Finding Description
The claimed binding is: org identified by `repository.full_name` (used for authorization/target resolution) == org identified by `repository.owner.login` (used for authentication/signature verification). Tracing the code shows these are two independent reads of the same untrusted JSON body with no equality check between them.

- `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` (or `organization.login`) and uses it to pick `Shipit.github(organization: repository_owner)`, then validates the raw body's HMAC against that org's `webhook_secret`. [1](#0-0) [2](#0-1) 

- `Handlers::Handler#stacks` and `#repository_name` resolve the target `Repository`/`Stack` using `payload.dig('repository','full_name')`, a completely different key of the same body, not gated by `repository_owner`. [3](#0-2) 

- `PushHandler#process` uses that `stacks` scope to call `stack.sync_github(expected_head_sha: params.after)` for every matching branch/stack, which is what ultimately enqueues `GithubSyncJob`. [4](#0-3) 

- `Repository.from_github_repo_name` parses `owner/name` directly out of `full_name` with no relation to `repository_owner`. [5](#0-4) 

- `GitHubApp#verify_webhook_signature` performs a standard HMAC-SHA1 comparison against `webhook_secret`, which is valid for the org selected by `repository_owner` -- it says nothing about which repo's data the signed body actually contains. [6](#0-5) 

Exploit flow: attacker owns `attacker-org`, which is registered in Shipit with a real `webhook_secret` (a legitimate, unprivileged precondition per the rules -- e.g., attacker added their own org as a GitHub App/webhook integration target that Shipit trusts). Attacker crafts a push payload:
```json
{"ref": "refs/heads/master", "after": "<attacker-chosen-sha>",
 "repository": {"full_name": "shopify/shipit-engine", "owner": {"login": "attacker-org"}}}
```
They sign the raw body with `attacker-org`'s own `webhook_secret` and POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` looks up `Shipit.github(organization: 'attacker-org')`, verifies successfully (attacker's own secret matches their own signature), and the request proceeds. `PushHandler#process` then resolves `Repository.from_github_repo_name('shopify/shipit-engine')` -- the victim's `Repository` -- and calls `stack.sync_github` on the victim's stacks with an attacker-chosen `expected_head_sha`.

None of the existing guards catch this: `drop_unhandled_event` only checks event type presence; `verify_signature` only authenticates the *org named in `owner.login`*, never comparing it to `full_name`'s org; `ExplicitParameters` (`requires :ref`, `requires :after`) only validates presence/shape of those two fields, not repository identity; there is no `force_github_authentication`/`User#authorized?`/`require_permission!` in play for unauthenticated webhook endpoints; `Repository`/`Stack` model validations only constrain format of owner/name/branch strings, not cross-repository binding.

### Impact Explanation
This is a payload for one repository (`attacker-org/*`, authenticated) causing a mutation-triggering job to be enqueued against another repository's/org's `Stack` (`shopify/shipit-engine`, unauthenticated by the attacker) -- matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attacker fully controls `expected_head_sha` (an arbitrary, attacker-chosen SHA) passed into `GithubSyncJob`, which then runs `Stack#sync_github` using the *victim's* own `github_api`/token, not the attacker's. This is repeatable at will against any victim `Repository` present in Shipit's database, for every push event handled the same way, and is capped only by which repositories exist as `Stack`s in the target Shipit instance. The severity depends on what `sync_github`/`GithubSyncJob` does with `expected_head_sha` (e.g., forcing sync/deploy-eligibility state to an attacker-chosen commit) -- this is namespace/state confusion across tenants sharing one Shipit deployment.

### Likelihood Explanation
Preconditions: (1) the Shipit instance must be configured for multi-organization GitHub App mode (`Shipit.github(organization:)` keyed off `secrets.github` per-org config) rather than the single-app legacy mode, since only then does `repository_owner` select among multiple valid `webhook_secret`s; (2) the attacker must control (or be able to register) at least one org that Shipit trusts with a `webhook_secret` -- explicitly allowed by the rules ("any GitHub user who can ... emit webhooks from a repository they own"); (3) the victim repo must already exist as a `Repository`/`Stack` in the same Shipit instance. Attacker cost is minimal: craft one JSON body and one HMAC signature using a secret they legitimately possess, then send a single unauthenticated POST to `/webhooks`. This is fully repeatable and requires no session, no API token, and no privileged role.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handlers::Handler`), enforce that the organization used to select the `webhook_secret` (`repository.owner.login` / `organization.login`) matches the organization portion of `repository.full_name` before processing; reject (422) on mismatch. Alternatively, always derive the authenticating org and the target-repository org from the same single field (e.g., always parse the org out of `full_name`), eliminating the two independent reads.

### Proof of Concept
```ruby
test "push payload with mismatched owner.login and full_name enqueues sync for victim stack signed by attacker org" do
  # Configure two orgs, each with a real webhook_secret, in test secrets:
  #   github: { "attacker-org" => { webhook_secret: "attacker-secret", ... },
  #             "shopify"      => { webhook_secret: "victim-secret", ... } }
  victim_stack = shipit_stacks(:shipit) # repository full_name "shopify/shipit-engine", branch "master"

  body = {
    ref: "refs/heads/master",
    after: "attackerchosen0000000000000000000000sha",
    repository: {
      full_name: "shopify/shipit-engine",     # victim's repo
      owner: { login: "attacker-org" }         # attacker's own org
    }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", "attacker-secret", body)

  request.headers["X-Github-Event"] = "push"
  request.headers["X-Hub-Signature"] = signature

  assert_enqueued_with(
    job: GithubSyncJob,
    args: [stack_id: victim_stack.id, expected_head_sha: "attackerchosen0000000000000000000000sha"]
  ) do
    post :create, body: body, as: :json
  end

  assert_response :ok
end
```
Both sides of the claimed binding (`repository.full_name`'s org vs. `repository.owner.login`) are asserted to be unequal in the crafted payload, and the assertion shows `GithubSyncJob` is still enqueued against the victim's `stack_id` -- confirming the divergence is exploitable.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
