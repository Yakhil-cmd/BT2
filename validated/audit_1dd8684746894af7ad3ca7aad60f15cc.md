### Title
Webhook signature verified against `repository.owner.login`, but stack lookup keyed on the unrelated `repository.full_name` field — cross-organization webhook forgery ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate a GitHub webhook against using `repository.owner.login` (or `organization.login`), but every event `Handler` resolves the target `Stack`/`Repository` to act on using the independent JSON field `repository.full_name`. Because the controller never checks that these two fields agree, a party who legitimately controls one organization's webhook secret in a multi-tenant Shipit install can forge a webhook payload that authenticates as their own organization while causing the handler to act on a completely different organization's repository/stack — the same "verify field A, act on field B" flaw described in the referenced report.

### Finding Description
`verify_signature` derives the signing organization purely from the payload: [1](#0-0) [2](#0-1) 

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: repository_owner)` is used only to pick the HMAC secret to validate `X-Hub-Signature` against [1](#0-0) . Once verification succeeds, the raw JSON body is dispatched unchanged to all registered handlers for the event: [3](#0-2) .

Every handler, however, resolves which `Stack`s to mutate from a *different* JSON key — `repository.full_name` — via the shared base class: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack of that repository whose branch matches [5](#0-4) , and `CheckSuiteHandler` schedules a check-run refresh for matching commits [6](#0-5) .

Nothing cross-checks that `repository.full_name` actually belongs to the organization identified by `repository.owner.login`/`organization.login` that was used to select the signing secret. In a Shipit instance configured for multiple GitHub organizations (each with its own entry — and its own legitimate `webhook_secret` — under `Shipit.github(organization: ...)`), an org that legitimately owns and administers its own webhook configuration can sign a payload as itself (`repository.owner.login` = "own-org", satisfying `verify_webhook_signature`) while setting `repository.full_name` = "victim-org/victim-repo". The signature check passes (it is computed over the whole raw body with the attacker's own valid secret), yet the handler acts on the victim repository's stacks.

This is structurally identical to the reported bug: the value used to authenticate the request (`repository.owner.login`, analogous to `inputAmount`) is not the value that downstream logic actually operates on (`repository.full_name`, analogous to `outputToken`'s pool), breaking the intended binding "organization that authenticated == repository that is written."

### Impact Explanation
An org that only has legitimate webhook credentials for its own repository can trigger actions against another organization's stacks it has no authorization over — a cross-repository/cross-organization write performed under a foreign trust boundary. Concretely this can force `stack.sync_github` calls (re-syncing GitHub state, potentially affecting mergeable/deployable status) and enqueue `RefreshCheckRunsJob` for a victim repository's commits, without the attacker having any access, membership, or webhook secret for the victim organization. This matches the "cross-repository writes" impact category.

### Likelihood Explanation
Exploitability requires the attacker to already have a legitimately provisioned `webhook_secret`/organization entry in the same multi-tenant Shipit deployment (e.g., as the admin of their own, unrelated GitHub organization onboarded onto the same Shipit instance) — a low but plausible bar in shared/SaaS-style Shipit installations serving several organizations. No repository write access, GitHub App key, or victim credentials are needed; only the attacker's own org's webhook secret and the ability to send an HTTP POST to `/github/webhooks`.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), require that `repository.full_name` (or `repository.owner.login` used by handlers) matches the organization that was used to select and validate the webhook secret, e.g. verify `payload.dig('repository','full_name')&.split('/')&.first&.casecmp?(repository_owner)` before dispatching to handlers, rejecting mismatches with a 422.

### Proof of Concept
1. Shipit instance configured with two organizations, `own-org` (attacker-controlled, valid `webhook_secret`) and `victim-org` (has a Stack tracking `victim-org/victim-repo`).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "own-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker signs the raw body with `own-org`'s webhook secret and sets `X-Hub-Signature` accordingly, sends to `POST /github/webhooks`.
4. `verify_signature` looks up `Shipit.github(organization: "own-org")` and validates successfully (attacker's own valid secret).
5. `PushHandler.stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github` on `victim-org`'s stacks, despite the request never being authenticated for `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
