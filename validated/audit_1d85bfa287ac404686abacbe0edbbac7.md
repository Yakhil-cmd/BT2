## Title
Cross-Organization Status Forgery via Global `sha` Lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The webhook signature check in `WebhooksController#verify_signature` selects which GitHub App/organization secret to validate against using an attacker-controlled field (`repository.owner.login` from the request body), and only proves that the request was signed by *some* configured organization's secret [1](#0-0) . Once past that check, `Shipit::Webhooks::Handlers::StatusHandler#process` resolves the target `Commit` purely by matching the attacker-supplied `sha` field against the entire `commits` table, with no scoping to the organization/repository whose secret authenticated the request [2](#0-1) . Because the `sha`/`stack_id` uniqueness constraint on `Commit` is per-stack, not global [3](#0-2) , the same SHA can independently exist in many stacks belonging to different organizations, and a caller authenticated as one (low-privilege) organization can write a forged CI status onto a commit belonging to a completely different organization/stack.

### Finding Description
`verify_signature` derives the signing organization from the JSON body itself (`repository.owner.login`, falling back to `organization.login`) before the signature has been checked, then verifies the raw body against that organization's `webhook_secret` [1](#0-0) . This only proves the request holder possesses the webhook secret for *whichever organization they named in the payload* — in a multi-tenant Shipit instance (as documented, `Shipit.github` supports multiple `organization` configs in `secrets.yml`), an attacker who legitimately administers their own onboarded GitHub org/App and knows its `webhook_secret` can produce a validly-signed request for event type `status`.

After signature verification, `WebhooksController#create` dispatches to `StatusHandler`, whose `process` method does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 

This lookup is **not scoped by repository or organization at all** — unlike `PushHandler`, which at least scopes through `Repository.from_github_repo_name(repository_name)` [4](#0-3) , `StatusHandler` inherits `repository_name`/`stacks` from `Handler` but never uses them, matching commits by `sha` across the entire `commits` table. Since `sha` + `stack_id` is only unique *per stack* (`add_index :commits, [:sha, :stack_id], unique: true`) [5](#0-4) , the same commit SHA can legitimately exist across many stacks (e.g. mirrored repos, shared history, or simply an attacker who knows/guesses a victim's public commit SHA and pre-seeds a matching commit in their own onboarded stack to make later re-verification trivial).

The result: the organization whose secret authenticated the webhook request has no enforced relationship to the stack/commit that actually receives the write, breaking the "organization that authenticated" vs. "commit/stack that is written" binding.

### Impact Explanation
`Commit#create_status_from_github!` creates a `Status` directly from unverified webhook fields with no re-check against the real GitHub API [6](#0-5)  path2="app/models/shipit/status.rb" start2="23" end2="33" />. `Status` creation has real side effects: it enables CI on the target stack (`enable_ci_on_stack`) and schedules continuous delivery (`schedule_continuous_delivery`) [7](#0-6) . A forged `success` status for a commit belonging to a stack the attacker does not control can satisfy required/blocking CI checks used to gate the merge queue and continuous deployment, leading to an unauthorized deploy of a commit that never actually passed CI in the victim organization/repository — this is a cross-repository/cross-tenant write with deploy-gating consequences, matching the Critical "cross-repository writes" / "unauthorized deploy" category.

### Likelihood Explanation
Exploitation requires only that the attacker control (or have legitimately onboarded) any single organization/App in the same multi-tenant Shipit deployment with a known `webhook_secret` — no access to the victim organization, no Shipit session, and no `ApiClient` token is needed. Commit SHAs are not secret (visible in GitHub UI/API, PR links, CI logs), and the attacker can pre-arrange for the same SHA to exist in a stack they control to confirm the technique, or simply target commits whose SHA they've observed in the victim stack. This is a purely code-level control gap (missing repository scoping in `StatusHandler`), not a misconfiguration or missing-secret scenario, so it is reachable in a properly configured deployment.

### Recommendation
Scope the `StatusHandler` lookup to the repository identified in the webhook payload, mirroring `PushHandler`/`Handler#stacks`, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
More broadly, bind the verified signing organization to the set of repositories/stacks a given webhook request is allowed to mutate, rather than trusting attacker-supplied repository/commit identifiers independently of which organization's secret authenticated the request.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, which is configured in this Shipit instance's `Shipit.github` config with a known `webhook_secret`.
2. Attacker observes (via GitHub's public API/UI) a commit SHA `S` belonging to `victim-org/victim-repo`, tracked by a Shipit stack the attacker cannot access.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "S",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
signed with `attacker-org`'s `webhook_secret` in `X-Hub-Signature`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates successfully [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: "S")`, which matches the victim's commit row (since the lookup is unscoped) and creates a forged `success` `Status` on it [2](#0-1) , potentially unblocking the victim's merge queue/continuous deployment.

### Uncertainty
I could not fully verify from the index alone how frequently real-world Shipit deployments configure multiple organizations with independently-controlled webhook secrets in production, nor whether `commits.sha` collisions across different stacks are common in practice versus requiring the attacker to seed a matching SHA themselves — both affect real-world likelihood but not the validity of the underlying missing-scoping bug in `StatusHandler`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** test/dummy/db/schema.rb (L79-86)
```ruby
    t.string "sha", limit: 40, null: false
    t.integer "stack_id", limit: 4, null: false
    t.datetime "updated_at"
    t.index ["author_id"], name: "index_commits_on_author_id"
    t.index ["committer_id"], name: "index_commits_on_committer_id"
    t.index ["created_at"], name: "index_commits_on_created_at"
    t.index ["sha", "stack_id"], name: "index_commits_on_sha_and_stack_id", unique: true
    t.index ["stack_id"], name: "index_commits_on_stack_id"
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
