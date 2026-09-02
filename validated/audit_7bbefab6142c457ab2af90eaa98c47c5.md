### Title
Webhook signature is bound to the payload's `repository.owner.login`, not to the `repository.full_name` the payload is dispatched against, allowing cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature with based on `repository.owner.login` (or `organization.login`) taken from the same untrusted JSON body it is about to verify. Once the signature check passes, event handlers (`Shipit::Webhooks::Handlers::Handler#stacks`) select which `Stack`/`Repository` to act on using a *different* field of that same body: `repository.full_name`. Because nothing ties the authenticated org (used to pick the secret) to the repository actually acted upon, any organization legitimately onboarded into `Shipit.github_apps` can sign a payload with its own valid `webhook_secret` while pointing `repository.full_name` at an unrelated stack, causing Shipit to treat the forged event as authentic for a repository the sender does not own.

### Finding Description
`verify_signature` computes `repository_owner` purely from the request body: [1](#0-0) [2](#0-1) 

It then fetches the GitHub App config for that organization and checks the HMAC using that org's own `webhook_secret`: [3](#0-2) 

Once verification succeeds, the full, unmodified `params` (the same attacker-controlled JSON) is dispatched to every registered handler for the event: [4](#0-3) 

Handlers resolve the target `Stack` using a **different** JSON path, `repository.full_name`, with no cross-check against `repository.owner.login`: [5](#0-4) 

`PushHandler` then acts on whatever stacks that lookup returns: [6](#0-5) 

The trust binding the signature is supposed to enforce is: *"the organization whose secret signed this request" == "the repository this event is applied to."* The code only proves the former (via `repository_owner`) and blindly trusts the latter (via `repository.full_name`) from the same forgeable body. Any organization already onboarded with its own valid `webhook_secret` (a normal, unprivileged tenant of a multi-org Shipit deployment) can therefore sign a payload with its own secret while setting `repository.full_name` to a completely different, unrelated stack's repository (e.g., `victim-org/victim-repo`), and the signature check will pass because it never validates that the signing org matches the acted-upon repository.

Other handlers act on payload fields directly rather than re-fetching authoritative state from the GitHub API — e.g. the `status` event handler builds a `Status` record straight from `target_url`, `state`, `description`, and `context` in the payload: [7](#0-6) 

This means the forged cross-repository event is not just a benign resync trigger — it can write attacker-chosen CI/commit-status data against a victim stack's commit.

### Impact Explanation
An attacker who controls (or is legitimately granted) any single organization/app registered in `Shipit.github_apps` can forge webhook events attributed to any *other* repository/stack configured in the same Shipit instance, without ever needing that other organization's `webhook_secret`. Depending on the handler, this allows:
- Forcing `GithubSyncJob` execution and repeated inaccessible/accessible state flips on a stack the attacker does not own.
- Writing forged commit statuses (`state`, `target_url`, `description`, `context`) onto commits of a victim stack, which can satisfy `ci.require` gating in that stack's `shipit.yml` and unlock automatic continuous deployment/merge of code the attacker never had access to.

This breaks the binding "an organization that authenticated versus the repository that is written," matching the High/Critical impact bar (escalation into cross-repository writes / triggering deploy-gating state on a repository outside the caller's authorization).

### Likelihood Explanation
Exploitation requires only a valid `webhook_secret` for *any* organization already configured in the multi-tenant Shipit deployment (`Shipit.github_apps`), which is a realistic unprivileged-attacker position in any Shipit instance serving more than one GitHub organization — the attacker never needs credentials for the victim organization/repository. No GitHub App private key, `api_clients_secret`, or Shipit session is needed; only the target instance being multi-org and the attacker controlling one tenant org's webhook secret (which that org's own GitHub App/webhook configuration legitimately possesses).

### Recommendation
In `WebhooksController#verify_signature` / `Handler#stacks`, enforce that the organization used to select the `webhook_secret` (`repository.owner.login` / `organization.login`) matches the owner segment of `repository.full_name` used to resolve the target `Stack`/`Repository`. Reject the event (e.g., `head(422)`) when these two identities diverge, so a signature from org A can never be used to act on org B's repositories.

### Proof of Concept
1. Attacker controls organization `attacker-org`, onboarded in `Shipit.github_apps` with its own legitimate `webhook_secret`.
2. Attacker crafts a `push` event body:
```json
{
  "ref": "refs/heads/master",
  "after": "<sha known to exist on victim-org/victim-repo>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s app config, and the HMAC check succeeds (the attacker legitimately knows this secret).
5. `PushHandler#stacks` resolves via `Repository.from_github_repo_name("victim-org/victim-repo")`, an org the attacker never authenticated as, and triggers `stack.sync_github(...)` (and, for handlers that persist payload content such as commit statuses, writes attacker-chosen state onto the victim stack's commit).

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
