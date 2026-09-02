### Title
Webhook Signature Verified Against `repository.owner.login`, But Target Repository Resolved From Unbound `repository.full_name` — Cross-Organization State Injection (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the HMAC signature against using `repository.owner.login` (or `organization.login`) from the JSON payload, while the handlers that actually act on the payload resolve the target `Repository`/`Stack` using the separate `repository.full_name` field. Because these are two independently attacker-controllable fields inside the same signed JSON body, and the signature only proves "whoever crafted this body knows the webhook secret associated with the org named in `repository.owner.login`," an attacker who knows the webhook secret for *any* organization configured on the Shipit instance can forge a payload whose `owner.login` matches their known org (to pass signature verification) while `full_name` points at an entirely different organization's repository, causing state-mutating webhook effects (sync commits, status updates, check-run refresh triggers) to be applied to a stack the attacker never authenticated for.

### Finding Description
`verify_signature` computes `repository_owner` and asks `Shipit.github(organization: repository_owner)` for the matching app config's `webhook_secret`, then verifies `X-Hub-Signature` against that secret: [1](#0-0) [2](#0-1) 

The `create` action then passes the *entire raw JSON payload* — unmodified and with no cross-check against `repository_owner` — to the event handlers: [3](#0-2) 

Every handler resolves the affected repository/stacks not from `repository.owner.login` but from a **different** field, `repository.full_name`: [4](#0-3) 

`Repository.from_github_repo_name` splits this string on `/` to get an independent owner/name pair used for the actual DB lookup: [5](#0-4) 

Because `repository.owner.login` (used for signature-secret selection) and `repository.full_name` (used for the actual write target) are two unrelated JSON keys that GitHub webhooks technically keep consistent, but which are *not cross-validated by the engine itself*, anyone able to author a raw HTTP POST with a valid HMAC for **some** organization's webhook secret can set these two fields to point at different owners. The equality the engine implicitly assumes — `verified_signature_org == acted_upon_repository_org` — is never actually checked in code.

Concretely: `PushHandler`, `StatusHandler`, and `CheckSuiteHandler` all call `stacks` (backed by `Handler#repository_name` / `full_name`) to find the target stack and then mutate its state (sync git HEAD, apply commit CI status, schedule check-run refresh): [6](#0-5) [7](#0-6) [8](#0-7) 

None of these consult `repository_owner`/the verified organization at all — they trust `full_name` unconditionally once the request clears `verify_signature`.

### Impact Explanation
On a Shipit deployment configured for multiple GitHub organizations (each with its own `webhook_secret` under `Shipit.github(organization: ...)`), an attacker who legitimately controls the webhook secret for Organization A (e.g., they administer a repo/App integration under Org A) can forge a raw webhook body where `repository.owner.login = "org-a"` but `repository.full_name = "org-b/victim-repo"`. `verify_signature` validates the HMAC using Org A's secret (which the attacker knows and used to sign), passes the request, and the handler then acts on Org B's stack using the attacker-supplied `full_name`, `sha`, `state`, `ref`/`after`, etc. This allows an attacker with no authorization over Org B to: force `sync_github` on Org B's stack with an attacker-chosen `expected_head_sha` (`PushHandler`), inject fabricated CI status onto Org B's commits (`StatusHandler`, which can gate/unblock deploys depending on stack CI requirements), or trigger check-run refresh jobs against Org B's commits (`CheckSuiteHandler`). This is a cross-organization/cross-repository write achieved purely by breaking the binding between "which secret validated this request" and "which repository the request is allowed to mutate," matching the High/Critical impact bar for unauthorized cross-repository writes and deploy-state manipulation.

### Likelihood Explanation
Exploitability requires only knowledge of one valid webhook secret for any organization configured on the instance — a realistic scenario for a multi-tenant or multi-organization Shipit deployment where different teams/orgs each register their own GitHub App/webhook integration into a shared engine, but do not otherwise trust each other's stacks. No GitHub session, `ApiClient` token, or Shipit login is required; the attacker interacts only with `WebhooksController#create`, an intentionally unauthenticated (signature-only) endpoint. This is a low-complexity, direct HTTP POST forgery once the secret for one org is known.

### Recommendation
Bind the signature-verification identity to the acted-upon repository: after verifying the HMAC, re-derive `repository_owner` from the exact same field the handlers use (`repository.full_name`'s owner segment, not `repository.owner.login`/`organization.login`), or better, have `verify_signature` and `Handler#repository_name` consult a single canonical field, and reject the request (422) if `repository.owner.login`/`organization.login` does not match the owner segment of `repository.full_name`. Additionally, consider scoping accepted webhook secrets per-repository rather than per-organization-name lookup keyed off attacker-supplied payload content.

### Proof of Concept
1. Attacker administers a GitHub App/webhook integration for `org-a`, giving them the true `webhook_secret` configured for `org-a` in Shipit (`Shipit.github(organization: 'org-a')`).
2. Attacker crafts a raw JSON body for a `push` event:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker_chosen_sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a_webhook_secret, body)` and POSTs to `/github/webhooks`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"org-a"` (from `owner.login`), fetches `org-a`'s webhook secret, and the HMAC matches → request passes.
5. `PushHandler#process` is invoked with the full payload; `Handler#repository_name` reads `payload.dig('repository','full_name')` = `"org-b/victim-repo"`, resolves `org-b`'s real `Stack`, and calls `stack.sync_github(expected_head_sha: "<attacker_chosen_sha>")` — mutating Org B's stack state despite the request only having been authenticated against Org A's secret.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
