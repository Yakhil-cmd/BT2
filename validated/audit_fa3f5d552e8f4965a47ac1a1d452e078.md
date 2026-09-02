### Title
Webhook signature verification keys off `repository.owner.login`, but handlers act on `repository.full_name` — cross-organization write via mismatched trust binding - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App / webhook secret used to authenticate an inbound webhook based on `repository.owner.login` (or `organization.login`) taken from the still‑unverified JSON body. Once the signature check passes, the actual event handlers (`Shipit::Webhooks::Handlers::Handler#repository_name`) resolve the `Repository`/`Stack` to act on using a **different** field of the same untrusted body: `repository.full_name`. Because these two sibling fields inside the attacker‑supplied payload are never cross‑checked for consistency, an attacker who legitimately knows the webhook secret for one configured GitHub organization (e.g., a customer administering their own GitHub App per `docs/setup.md`'s "Using Multiple GitHub Applications" flow) can forge a request that is verified as coming from "their" org but whose `repository.full_name` points at a stack belonging to a completely different, unrelated organization hosted on the same Shipit instance.

### Finding Description
`verify_signature` derives the org used to look up the secret purely from the payload itself, before any authentication has occurred: [1](#0-0) [2](#0-1) 

Once `head(422)` is not triggered, the raw params are handed unmodified to the registered handlers: [3](#0-2) 

Every handler resolves the target `Repository`/`Stack` via a *different* field of the same JSON body: [4](#0-3) 

`Repository.from_github_repo_name` parses `owner/name` straight out of that `full_name` string with no relation whatsoever to which org's secret validated the request: [5](#0-4) 

The binding the code implicitly relies on is:
`organization whose secret validated the HMAC == organization that owns the repository/stack being acted upon`

That equality is never enforced. Both `repository.owner.login` and `repository.full_name` are attacker‑controlled fields inside the same self‑authored HTTP body (Shipit's multi‑org deployment explicitly supports several independent GitHub Apps/secrets on one instance — see `docs/setup.md`, "Using Multiple Github Applications"). Anyone who knows a valid webhook secret for *any one* configured organization (they set it themselves when registering their own GitHub App, per the setup guide) can compute a correct HMAC over a body whose `repository.owner.login` matches that org (so `verify_signature` passes) while `repository.full_name` names a stack under a *different* organization on the same Shipit instance. The event is then dispatched to that stack's handlers as if it were an authentic event for that repository, e.g. `push` events queue `GithubSyncJob` with an attacker‑chosen `expected_head_sha` (`params["after"]`) against a victim stack that never authenticated this request: [6](#0-5) 

The `pull_request` handlers exhibit the identical pattern — they independently re‑resolve the repository from `params.repository.full_name` for authorization decisions (e.g. auto‑provisioning review stacks) with no tie‑back to the verified organization: [7](#0-6) 

This is the direct analog of the reported bug class: a value used to satisfy an authorization/authentication gate (`repository_owner` used to pick the signing key) is not the same value that downstream mutation logic actually acts on (`repository.full_name`), producing a broken deployment‑trust binding — "an organization that authenticated versus the repository that is written."

### Impact Explanation
An attacker controlling one legitimately-configured GitHub organization on a shared, multi‑org Shipit deployment can craft webhook payloads that are cryptographically valid for their own org but drive state changes on stacks/repositories belonging to unrelated organizations they have no access to — cross‑repository writes (enqueuing sync/PR‑handling jobs, injecting attacker‑chosen commit SHAs as `expected_head_sha`, forcing review‑stack provisioning/closing on foreign repositories) without ever being authenticated for the targeted organization. This matches the "cross‑repository writes" / unauthorized‑action impact bar.

### Likelihood Explanation
Requires only knowledge of one legitimately obtained webhook secret (something a customer admin configuring their own GitHub App per the documented setup already possesses) and the ability to POST an arbitrary, self-signed body to the public `/webhooks` endpoint — no GitHub compromise, no Shipit session, and no privileged Shipit account is needed. This is realistic in any deployment following the documented multi‑organization configuration.

### Recommendation
After `verify_signature` succeeds, bind the verified organization to the rest of request processing: pass the verified `repository_owner`/organization down to handlers and require that `repository.full_name`'s owner segment (and/or `organization.login`) match the organization whose secret validated the signature before resolving any `Repository`/`Stack`. Reject the webhook (422) on mismatch.

### Proof of Concept
1. Deploy Shipit configured with two organizations per `docs/setup.md`'s multi-app example: `OrgA` (victim, has a Shipit `Stack` for `OrgA/victim-repo`) and `OrgB` (attacker-administered, attacker knows `OrgB`'s `webhook_secret` because they configured it themselves).
2. Attacker crafts a raw JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/victim-repo" }
}
```
3. Attacker computes `sha1=HMAC(OrgB_webhook_secret, body)` and sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<computed>
```
4. `WebhooksController#verify_signature` computes `repository_owner = "OrgB"`, fetches `Shipit.github(organization: "OrgB")`, verifies successfully (attacker used the correct secret for `OrgB`).
5. `PushHandler` (dispatched via `Handler#stacks`/`#repository_name` reading `repository.full_name`) resolves `Repository.from_github_repo_name("OrgA/victim-repo")` and enqueues `GithubSyncJob` with `expected_head_sha` = attacker's chosen SHA against `OrgA`'s stack — a write to a stack the attacker was never authenticated against.

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

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
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
