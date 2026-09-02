### Title
Cross-repo/cross-stack commit status forgery via unscoped `StatusHandler#process` defeats CI gating on every `ignore_ci?: false` stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Commit#deployable?` only bypasses CI when `stack.ignore_ci?` is `true`; for every other stack it relies on `success?`, which is derived from `Status` rows written by `StatusHandler#process`. That handler resolves target commits with `Commit.where(sha: params.sha)` with no repository binding, so a legitimately-signed webhook for one repository can flip the CI status of a `Commit` record belonging to a completely different stack whose commits happen to share the same sha (forks, mirrors, or multiple stacks/environments tracking the same repository). No configuration in `Stack` or `DeploySpec` narrows this beyond `ignore_ci`.

### Finding Description
Binding to verify: `exposure_to_forgery(stack) == !stack.ignore_ci?` for every stack, with no other mitigating flag in `Stack`/`DeploySpec`.

- `Commit#deployable?` is defined as: [1](#0-0) 
`!locked? && (stack.ignore_ci? || (success? && !blocked?))`. When `stack.ignore_ci?` is `true`, the whole `success?`/`blocked?` branch is short-circuited — deployability never touches CI state (confirmed by `test/models/commits_test.rb:558-562`: `"#deployable? is true if stack is set to 'ignore_ci'"`). So for `ignore_ci?: true` stacks, a forged status is a no-op: the commit was already deployable.
- For `ignore_ci?: false` (the model default, added by `db/migrate/20150518214944_add_ignore_ci_to_stack.rb` with no explicit default, i.e. `false`/`nil`), `deployable?` depends on `success?`, delegated to `status`: [2](#0-1) 
`status` is populated purely from `Status` records written via `create_status_from_github!` / `add_status`.
- The webhook path that writes those records is: [3](#0-2) 
`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. This looks up commits **by sha only**, across the entire instance, and updates every match.
- The base `Handler` class provides repository-scoping helpers (`stacks`, `repository_name` derived from `payload.dig('repository', 'full_name')`): [4](#0-3) 
but `StatusHandler#process` never calls them — it ignores `payload['repository']` entirely.
- `WebhooksController#verify_signature` only proves the request is a validly-signed GitHub delivery for `repository_owner` (taken straight from the attacker-influenced payload) via `Shipit.github(organization: repository_owner)`: [5](#0-4) 
It does **not** verify that the `sha` in the payload actually belongs to that repository — that binding is simply absent from the code path, so a legitimate webhook from repo A's own CI (or repo A's owner posting a commit status via the GitHub API) can carry any `sha`, and `StatusHandler` will apply it to every `Commit` row across every stack that shares that sha (e.g., two stacks/environments tracking the same GitHub repository, or a stack tracking a fork that shares history/objects with the original).
- No mitigating field exists in `Stack` or `DeploySpec`: the only knobs found are `ignore_ci`, `required_statuses`, `blocking_statuses`, `hide`/`allow_failures` (all in `app/models/shipit/deploy_spec.rb`), none of which validate the origin repository of an incoming status. `stacks_controller.rb`/`_settings_form.erb` expose only `ignore_ci` as a per-stack toggle related to CI gating.

### Impact Explanation
For any stack with `ignore_ci?: false` (the default), an attacker who can trigger a genuinely-signed GitHub webhook (e.g., by pushing a commit status from a repository they control that shares a sha with a tracked stack, such as via a fork of the victim's public repository, or another stack on the same physical repo) can set `state: success` on a `Commit` they do not own, flipping `Commit#deployable?` to `true` and enabling `stack.trigger_deploy`/`next_commit_to_deploy` to treat unreviewed/unbuilt code as deployable. This is a payload from one repository mutating another stack's commit state, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy"). Blast radius: every `ignore_ci?: false` stack in the instance is exposed (`ignore_ci?: true` stacks gain nothing from this, since they are already unconditionally deployable per `Commit#deployable?`).

### Likelihood Explanation
Preconditions: attacker needs (a) at least one repository/organization already known to Shipit for signature verification to pass legitimately, and (b) a commit sha collision between that repository and the victim stack's commit history — most realistically achieved via a public fork (git forks share commit objects/shas with upstream) or via multiple Shipit stacks tracking the same underlying repository (common: staging/production/review-stack setups). No Shipit session, API token, or secret is required; the attacker only needs ordinary GitHub actions (fork, push, set a commit status via the GitHub API on their own repo) that legitimately trigger a correctly-signed webhook delivery. This is repeatable per commit/per stack.

### Recommendation
Scope `StatusHandler#process` (and any other sha-keyed handler) to the repository named in the webhook payload, e.g. restrict the `Commit.where(sha: params.sha)` lookup to `stacks` (via `Repository.from_github_repo_name(repository_name)`) as the base `Handler` class already supports, instead of matching by sha across the whole instance.

### Proof of Concept
```ruby
test "StatusHandler#process updates commits from unrelated repositories sharing the same sha" do
  stack_a = shipit_stacks(:shipit)          # repository "shipit", ignore_ci: false
  stack_b = shipit_stacks(:cyclimse)        # repository "cyclimse", ignore_ci: false, different repo

  shared_sha = "a" * 40
  commit_a = stack_a.commits.create!(sha: shared_sha, message: "a")
  commit_b = stack_b.commits.create!(sha: shared_sha, message: "b")

  refute_predicate commit_b, :deployable? # baseline: unknown status, not deployable

  # Attacker triggers a legitimately-signed webhook for repo "shipit" only
  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'repository' => { 'full_name' => 'shopify/shipit' } # only repo A named
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  commit_b.reload
  assert_equal 'success', commit_b.state
  assert_predicate commit_b, :deployable? # stack B commit now deployable despite webhook naming repo A only
end
```

### Citations

**File:** app/models/shipit/commit.rb (L219-219)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
