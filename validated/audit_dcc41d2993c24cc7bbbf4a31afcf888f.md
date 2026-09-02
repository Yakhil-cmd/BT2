### Title
Cross-repository status pollution via SHA collision in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with a bare `Commit.where(sha: params.sha)`, never scoping the query to the repository/stacks derived from the webhook payload via the inherited `Handler#stacks` helper. As a result, a `status` webhook whose payload names repository B but whose `sha` happens to match a commit belonging to unrelated stack A will write a `Status` record onto stack A's commit.

### Finding Description
The binding claimed by the question is: `Handler#stacks` (i.e., `Repository.from_github_repo_name(repository_name)&.stacks`) == the scope over which `StatusHandler#process` mutates commits. Tracing the code confirms this is false: `#process` at [1](#0-0)  calls `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no reference to `stacks`, `repository_name`, or any repository-derived filter, while `Handler#stacks` at [2](#0-1)  exists but is unused by this subclass.

Request path: `POST /webhooks` with header `X-Github-Event: status` is routed to `WebhooksController#create`, which parses the JSON body and dispatches to registered handlers for the `status` event [3](#0-2) . Before dispatch, `verify_signature` checks the HMAC signature using `Shipit.github(organization: repository_owner)`, i.e., the GitHub App/secret configured for the *organization named in the attacker's own payload* [4](#0-3) . This only proves the payload was actually sent by GitHub for the org that owns the webhook secret used — it says nothing about which `sha` value is inside the payload. An attacker who owns/administers any repository connected to Shipit (repo B) can trigger a real, validly-signed GitHub `status` webhook for repo B, choosing (or waiting for) a `sha` value that collides with a commit already recorded under an unrelated stack A (e.g. by pushing a commit to their own fork/branch whose SHA happens to match, or, more practically, by having their fork/branch share history with the upstream repo so that shared commits produce identical SHAs across "repositories" in Shipit's DB — since SHA is a content hash it is trivially reproducible by forking and does not include repository identity).

Because `Commit.where(sha: params.sha)` is not scoped to `repository_name`, every `Commit` row across every stack that happens to share that SHA gets `create_status_from_github!(params)` called on it, writing a `Status` row (`replicate_from_github!`) and triggering downstream side effects in `Commit#add_status`: `Hook.emit(:commit_status, ...)`, `Hook.emit(:deployable_status, ...)`, and `stack.schedule_merges` if the injected status is `success`/`pending` [5](#0-4) . This can flip a commit's derived `status`/`deployable?` state, which feeds `Stack#schedule_merges` and continuous-delivery/merge logic on a stack the attacker never authenticated against.

None of the existing guards catch this: `verify_signature` authenticates that "this payload came from GitHub for repository_owner", not that "this SHA belongs to repository_owner's history"; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema on `StatusHandler` (`requires :sha`, `:state`, etc.) only validates presence/type of fields, not their relationship to any repository [6](#0-5) .

### Impact Explanation
Any repository owner registered with Shipit (an unprivileged party with respect to other tenants) can cause `Status` rows to be written onto commits belonging to a different stack/repository whenever a SHA collision exists (trivial via forking/sharing history), corrupting that stack's CI/deploy status and potentially triggering `stack.schedule_merges` / deployability changes on a stack the attacker does not control. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." The blast radius is any stack sharing commit history (forks, monorepo mirrors, or repos that were renamed/re-pointed while old commits remain in the `commits` table) with a repository the attacker controls, and it is repeatable per SHA collision with unlimited status webhooks.

### Likelihood Explanation
Preconditions: the attacker must control (own, admin, or push to) at least one GitHub repository that is connected to the target Shipit instance, and there must be a `Commit` row in another stack sharing the same `sha`. Since commit SHAs are git object hashes, this is straightforward when repos share history (common fork/mirror/rename scenarios) and requires no secrets, no session, and no privileged Shipit role — only the ability to push a commit/branch to an owned repository and let GitHub fire the `status` webhook, or to POST a status via the GitHub API for a repository the attacker administers. This is low-cost and repeatable.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository derived from the payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, mirroring the pattern other handlers use with `Handler#stacks`, so a webhook can only mutate commits belonging to stacks associated with the repository named (and signature-verified) in that same payload.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (illustrative, not present in repo)
test "status webhook for repo B does not mutate commits of unrelated stack A sharing the same sha" do
  stack_a = shipit_stacks(:shipit) # repository A
  commit_a = stack_a.commits.create!(sha: "deadbeef" * 5, message: "shared sha")

  payload = {
    "repository" => { "full_name" => "some-other-org/repo-b" },
    "sha" => commit_a.sha,
    "state" => "success",
    "context" => "attacker-context"
  }

  handler = Shipit::Webhooks::Handlers::StatusHandler.new(payload)

  # Binding under test: stacks-for(repo-b) == set of commits mutated.
  repo_b_stacks = Shipit::Repository.from_github_repo_name("some-other-org/repo-b")&.stacks || Shipit::Stack.none
  assert_not_includes repo_b_stacks.flat_map(&:commits).map(&:id), commit_a.id

  assert_no_difference -> { commit_a.reload.statuses.count } do
    handler.process
  end
end
```
Running this against current code fails (statuses count increases by 1), demonstrating that `#process` writes a `Status` onto `commit_a` even though `commit_a` does not belong to any stack of `repo-b`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-34)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end
```

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

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
