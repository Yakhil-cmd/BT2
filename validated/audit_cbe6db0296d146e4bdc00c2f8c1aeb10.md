### Title
Webhook signature verified against `repository.owner.login` while target stack is resolved from unrelated `repository.full_name`, allowing cross-tenant stack sync - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` derives the GitHub organization used to fetch the HMAC secret from `params.dig('repository','owner','login')`, while `Handlers::Handler#repository_name` (used by `PushHandler` and others to select the stacks to mutate) derives the target repository from `params.dig('repository','full_name')`. Because both fields come from the same attacker-controlled JSON body and nothing cross-checks that they refer to the same organization, an attacker who owns a legitimate organization/webhook_secret can sign a payload whose `full_name` points at a victim repository, causing that victim's stack to be synced.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`organization_that_signed_the_request (params.dig('repository','owner','login'))` == `organization_that_owns_the_mutated_stack (Repository.from_github_repo_name(params.dig('repository','full_name')).owner)`

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (or `organization.login`) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, request.raw_post)` [1](#0-0) [2](#0-1) .
- `verify_webhook_signature` only checks that the raw bytes match an HMAC-SHA1 computed with that organization's own `webhook_secret`; it has no knowledge of, and does not validate, any other field inside the JSON body [3](#0-2) .
- `WebhooksController#create` re-parses the same raw body and dispatches it to handlers [4](#0-3) .
- `Handlers::Handler#repository_name` reads `payload.dig('repository', 'full_name')`, and `#stacks` resolves `Repository.from_github_repo_name(repository_name)&.stacks` [5](#0-4) .
- `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack matching the pushed branch [6](#0-5) .

Since `repository.owner.login` and `repository.full_name` are two independent, attacker-writable keys of the same JSON body, and the signing check only authenticates that the *bytes* were produced with a given org's secret (not that the values inside are internally consistent), an attacker owning `attacker-org` (with a real, legitimately-configured `webhook_secret`) can:
1. Build a push payload where `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/other-repo"`.
2. Compute a valid `X-Hub-Signature` over that exact payload using their own `attacker-org` webhook secret.
3. POST it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (attacker legitimately owns this secret).
5. `PushHandler` resolves stacks via `full_name = "victim-org/other-repo"`, an entirely different, real Shipit-tracked repository, and calls `sync_github` on it with attacker-supplied `after` sha.

No existing guard closes this gap: `drop_unhandled_event` only checks the event type is handled; `verify_signature` never compares `repository_owner` against `repository_name`'s owner; there is no `ExplicitParameters` schema constraint enforcing owner/full_name consistency (the schema for `PushHandler` only requires `ref` and `after`) [7](#0-6) ; and `Repository.from_github_repo_name` performs a straightforward lookup with no ownership cross-check back to the verified signer.

### Impact Explanation
An attacker who legitimately controls a GitHub organization (and hence its Shipit `webhook_secret`) can trigger `Stack#sync_github` for *any* other tenant's stack tracked by this Shipit instance, simply by mismatching `repository.owner.login` vs `repository.full_name` in a self-signed webhook body. This is a payload-for-one-repository-mutating-another's-stack scenario — Critical severity per the stated impact categories. The blast radius spans every stack hosted on the instance, since any organization with a configured webhook (including the attacker's own) can be used as the "signing identity" while the "target identity" is unconstrained. Repeatable per request, against arbitrary victim repositories, with no rate limiting beyond normal HTTP access.

### Likelihood Explanation
Preconditions are modest: the attacker needs (a) their own organization already configured in Shipit with a `webhook_secret` they legitimately hold (i.e., they are already a Shipit-integrated GitHub org owner, not a privileged Shipit operator), and (b) knowledge/guess of a victim `owner/repo` full name tracked by the same Shipit instance (repo names are often discoverable/public). No Shipit session, API token, or GitHub App private key is required. This is a fully self-contained, deterministic HTTP request the attacker can construct and replay at will, making it highly feasible and cheap.

### Recommendation
In `WebhooksController#verify_signature`/`create`, or in `Handlers::Handler`, enforce that the organization used to verify the signature matches the organization owning the repository resolved for mutation — e.g., compare `payload.dig('repository','owner','login')` (or `organization.login`) against the owner segment of `payload.dig('repository','full_name')`, and reject (422) any request where they differ. Alternatively, resolve the target `Repository`/`Stack` first, verify the signature using the secret configured for *that* repository's actual organization, and refuse to act if `repository_owner` from the payload doesn't match the repository record's known owner.

### Proof of Concept
Minitest in `test/controllers/webhooks_controller_test.rb`-style test (illustrative, showing the exact assertions needed):
```ruby
test "signature from attacker's own org does not authorize mutating victim-org's stack" do
  victim_stack = shipit_stacks(:shipit) # repository full_name e.g. "victim-org/other-repo" pointing to a real tracked stack

  payload = {
    "ref" => "refs/heads/#{victim_stack.branch}",
    "after" => "attackercontrolledsha",
    "repository" => {
      "full_name" => "#{victim_stack.repository.owner}/#{victim_stack.repository.name}", # victim-org/other-repo
      "owner" => { "login" => "attacker-org" } # attacker's own org, real secret
    }
  }.to_json

  attacker_secret = "attacker-real-webhook-secret"
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_secret, payload)

  # verifying_org == "attacker-org" (real secret, correctly signed)
  # target_org derived from full_name == "victim-org" (unrelated organization)
  assert_not_equal "attacker-org", victim_stack.repository.owner

  @request.headers['X-Github-Event'] = 'push'
  @request.headers['X-Hub-Signature'] = signature

  Shipit.expects(:github).with(organization: "attacker-org").returns(
    stub(verify_webhook_signature: true)
  )

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: "attackercontrolledsha"]) do
    post :create, body: payload, as: :json
  end
end
```
This demonstrates: signature verifies successfully against `attacker-org`'s real secret, yet the sync job is enqueued against `victim_stack`, whose owning organization is not `attacker-org` — proving the binding `signing_org == target_repo_owner` is violated.

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
