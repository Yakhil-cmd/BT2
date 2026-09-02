### Title
Cross-repository Status forgery via `StatusHandler#process`'s unscoped SHA lookup bypasses `require_ci` on `Api::DeploysController#create` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with a global `Commit.where(sha: params.sha)` query that ignores which repository/stack the incoming, validly-signed webhook belongs to. Any commit sharing the same SHA across unrelated stacks (trivially achievable via a fork, since git commit SHAs are content-addressed) receives the status, making `Commit#deployable?` true for a victim stack even though CI never ran against that stack's own repository/webhook.

### Finding Description
The broken binding: `Status.stack_id` (and therefore `Commit#deployable?`'s underlying `success?`) should only ever equal `true` for statuses whose provenance repository equals `commit.stack.repository`. In code:

- `StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 
This lookup is by `sha` alone, with no `stack_id`/repository filter, across the entire `commits` table.

- `Commit#create_status_from_github!` then writes the status scoped to *that commit's own* `stack_id`, not the webhook payload's repository:
```ruby
def create_status_from_github!(github_status)
  add_status do
    statuses.replicate_from_github!(stack_id, github_status)
  end
end
``` [2](#0-1) 

- `Commit#deployable?` consults exactly this state:
```ruby
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [3](#0-2) 

- `verify_signature` in `WebhooksController` only validates that the payload's `repository.owner.login`/`organization.login` matches a known GitHub App organization — it authenticates *that the sender legitimately owns the org/repo it claims*, but does nothing to constrain which `Commit` rows in the database get updated:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  head(422) unless verified
end
``` [4](#0-3) 

Root cause: git commit SHAs are content-addressed hashes of tree/parent/author/committer/message — if a victim repository's commit is forked unmodified into an attacker-controlled repository that is *also* onboarded as its own Shipit stack (which any GitHub user can do by adding a webhook to their own fork), the identical SHA exists in both stacks' `commits` tables. When the attacker's own repository legitimately fires a `status` webhook (signed correctly by GitHub for the attacker's org — no secrets needed by the attacker beyond controlling their own fork/CI), `StatusHandler#process` matches ALL `Commit` rows with that SHA, including the victim's, and writes a `success` `Status` under the victim stack's `stack_id` via `create_status_from_github!`. This makes the victim's `Commit#deployable?` return `true` without the victim's own CI or webhook ever running.

Later, an operator who is legitimately authorized only for the victim stack calls `POST /api/stacks/:id/deploys` with `require_ci: true`. `Api::DeploysController#create`'s require_ci check consults `commit.deployable?`, which is now poisoned, and the deploy proceeds (202) instead of being rejected (422) — even though CI never ran under the victim's own repository/webhook_secret.

No existing guard stops this: `verify_signature` correctly authenticates the attacker's own org/repo, but that is irrelevant since the vulnerable write in `StatusHandler#process` is not scoped to the authenticated repository at all — it operates purely on SHA. `drop_unhandled_event`, `ExplicitParameters` schema (`requires :sha`, `requires :state`, etc.), and `Commit#deployable?`'s own logic all assume `Status` rows are trustworthy per-stack, an assumption `StatusHandler` breaks.

### Impact Explanation
An unprivileged GitHub user (owner of any fork of a target repository that is separately onboarded into the same Shipit instance) can inject a fabricated-context "success" status into a victim stack's commit, tricking `Commit#deployable?` and, in turn, `Api::DeploysController#create`'s `require_ci` safety check, causing a stack-scoped operator's otherwise-legitimate, properly-authorized deploy request to ship a commit whose CI never passed under its own repository. This is a cross-tenant record write (a payload for one repository mutating another repository's stack/commit state) leading to an unauthorized deploy bypass — Critical severity, per the rubric's "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." It is repeatable against any stack that shares a fork relationship (or otherwise has commits with colliding SHAs) with a repository the attacker controls, and is not limited to one victim.

### Likelihood Explanation
Preconditions: (1) the victim repository must be public/forkable and forked by the attacker (trivial, standard GitHub feature); (2) the attacker's fork must be onboarded into the same Shipit instance as its own stack (feasible if Shipit onboarding for new repos is self-service or the attacker has any repo already onboarded, e.g. `Shipit::WebhooksController` handles unknown repos gracefully per `test "create github repository which is not yet present in the datastore"`); (3) the same unmodified commit (identical SHA) must exist in both the attacker's fork and the victim's stack, which happens naturally whenever the victim's commit is present upstream of the fork; (4) a legitimate operator must later call the deploy API with `require_ci: true` for that SHA. No Shipit secrets are required by the attacker — GitHub signs the attacker's own webhook legitimately. This is a design flaw reachable purely through normal fork/CI workflows.

### Recommendation
Scope the `StatusHandler#process` lookup (and the underlying status write) to commits belonging to a stack whose repository matches the webhook payload's `repository.full_name`/`repository_id`, e.g. `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: repository.id })`, instead of a bare SHA match across all stacks. Alternatively, key `Status` records by repository provenance and require `Commit#deployable?`/`success?` to only consider statuses whose repository matches `commit.stack.repository`.

### Proof of Concept
In `test/models/webhooks/handlers/status_handler_test.rb` (or equivalent), minitest plan:
1. Create two stacks, `victim_stack` (repo `victim/repo`) and `attacker_stack` (repo `attacker/fork`), and create a `Commit` with an identical `sha` = `"deadbeef1234"` under each stack, with `victim_commit.statuses` empty (so `victim_commit.deployable?` is `false`).
2. Assert precondition: `refute victim_commit.deployable?`.
3. Invoke `StatusHandler.new.process` (or POST to `/webhooks` with `X-Github-Event: status`, a payload whose `repository.full_name == 'attacker/fork'`, signed with the attacker's org's legitimate secret) with `sha: "deadbeef1234", state: "success"`.
4. Assert `victim_commit.reload.deployable?` is now `true` even though no status referencing `victim/repo` was ever produced — proving the binding `Status.stack_id == commit_for(sha).stack_id via attacker-authenticated payload, regardless of repository` is broken.
5. In `test/controllers/api/deploys_controller_test.rb`, with an `ApiClient` scoped only to `victim_stack`, `POST :create, params: { stack_id: victim_stack.to_param, sha: victim_commit.sha, require_ci: true }` and assert `assert_response :accepted` (202) instead of the expected `:unprocessable_entity` (422), demonstrating the require_ci bypass caused by the forged cross-repo status.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
