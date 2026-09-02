### Title
Unscoped `Commit.where(sha: params.sha)` in `StatusHandler#process` lets one signed webhook mutate Commit/Status rows of every stack sharing that SHA - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commit(s) with a bare `Commit.where(sha: params.sha).each`, with no `stack_id`/repository scoping, unlike `Commit.by_sha`/`by_sha!` which are always invoked through a stack-scoped association (`stack.commits.by_sha!`). Any commit sha that happens to be recorded in more than one stack's `commits` table (e.g. forks, mirrors, monorepo splits, or a repo tracked by multiple stacks) will have its status mutated in **all** of them from a single incoming webhook.

### Finding Description
The claimed binding is: `Commit.where(sha: params.sha)` == `Commit.by_sha!(params.sha)` scoped to the stack that owns the webhook — i.e., "one webhook payload mutates at most one Commit row (the one belonging to the authenticated repository's stack)". Tracing the code shows this does **not** hold:

- `StatusHandler#process` at [1](#0-0)  runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, class-level query against the entire `commits` table, with no filter on `stack_id`, `repository`, or the webhook's `repository_owner`.
- By contrast, `Commit.by_sha`/`by_sha!` at [2](#0-1)  only guard against *prefix ambiguity* (multiple commits matching a short-sha prefix); they are always called through a stack-scoped relation (e.g. `stack.commits.by_sha!`) elsewhere in the codebase, so their ambiguity check is local to one stack, not a cross-tenant guard.
- `WebhooksController#verify_signature` at [3](#0-2)  authenticates that the payload came from GitHub for the organization named in `params.dig('repository','owner','login')` — it does **not** constrain which `Commit`/`Stack` rows the payload's `sha` is allowed to touch. Once signature verification passes, `StatusHandler` is free to write to any Commit row in the database that has a matching `sha` column value, regardless of which repository/organization the webhook came from.

Root cause: the handler treats `sha` as if it were a globally-authoritative unique key, but `commits.sha` has no uniqueness constraint across stacks — the same 40-hex value can legitimately be duplicated across many `Stack` records (forked repos retain identical commit objects/SHAs, monorepo splits, repo re-imports/renames, or the same GitHub repo tracked by multiple stacks for different branches/environments).

### Impact Explanation
A single "status" webhook event, correctly signed for the attacker's own onboarded repository/organization, causes `create_status_from_github!` to run once per matching `Commit` row across **every** stack that happens to store that sha — writing a forged `Status` (state/description/target_url/context all attacker-controlled) onto commits belonging to unrelated stacks/tenants. This matches the "payload for one repository mutating another's stack" Critical category: it can flip a victim stack's CI/deployability signal (`Commit#deployable?`, `Commit#status`) without that stack's own GitHub repository ever sending the event, potentially unblocking or blocking deploys and lock/merge automation (`stack.schedule_merges`, `ContinuousDeliveryJob`) for a tenant the attacker does not control. Blast radius scales with however many stacks independently persisted a Commit row with the colliding sha.

### Likelihood Explanation
Exploitability depends entirely on being able to get a `sha` value that already exists as a `Commit` row in a victim stack while also controlling a webhook that is legitimately signed for some registered repository/organization. Genuine SHA-1 preimage/collision is not attacker-feasible, so in practice this requires a real-world scenario where the exact same commit object (same tree, parents, author, committer, timestamps) is independently tracked by two different stacks — e.g. a forked/mirrored repository, a renamed/re-imported repo, or the same upstream repo intentionally tracked by several stacks (staging/production). `verify_signature` still requires the organization named in the payload to be a Shipit-configured GitHub App/org (`Shipit.github(organization: repository_owner)`), so the attacker must already have push/status-posting rights on a repository belonging to an organization that is a legitimate tenant of this Shipit instance. Given that precondition, the attack costs a single webhook-triggering action (e.g. posting a commit status via the GitHub API) and is fully repeatable.

### Recommendation
Scope the lookup to the stack(s) actually associated with the webhook's repository, e.g. resolve via `Repository`/`Stack` from `params.dig('repository','full_name')` and filter `Commit.where(sha: params.sha, stack_id: matching_stack_ids)`, or add an explicit `Stack` → `Repository` join constraint before iterating, so a webhook can only mutate commits belonging to stacks whose `Repository` matches the authenticated payload.

### Proof of Concept
```ruby
test "StatusHandler#process fans out a single payload across every stack sharing a sha" do
  sha = "a" * 40
  stacks = 4.times.map { |i| shipit_stacks(:shipit) } # or create 4 distinct Stack fixtures
  commits = stacks.map { |stack| Shipit::Commit.create!(stack: stack, sha: sha, message: "m") }

  assert_difference -> { Shipit::Status.count }, 4 do
    Shipit::Webhooks::Handlers::StatusHandler.call(
      Shipit::Webhooks::Params.new(sha: sha, state: "success", context: "ci/attacker")
    )
  end

  assert_equal 4, commits.map(&:reload).map(&:stack_id).uniq.size
  commits.each { |c| assert_equal "success", c.status.state }
end
```
This demonstrates that one `StatusHandler.call` invocation mutates Commit/Status state across 4 distinct `stack_id`s, breaking the "one payload → at most one Commit row" binding, with no live GitHub interaction required.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L92-103)
```ruby
    def self.by_sha(sha)
      raise AmbiguousRevision, "Short SHA1 #{sha} is ambiguous (too short)" if sha.to_s.size < 6

      commits = where('sha like ?', "#{sha}%").take(2)
      raise AmbiguousRevision, "Short SHA1 #{sha} is ambiguous (matches multiple commits)" if commits.size > 1

      commits.first
    end

    def self.by_sha!(sha)
      by_sha(sha) || raise(ActiveRecord::RecordNotFound, "Couldn't find commit with sha #{sha}")
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```
