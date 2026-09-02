### Title
Cross-repository commit status forgery via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` rows solely by `sha`, with no join or filter on the repository/stack that the webhook payload claims to originate from. Because git commit SHAs are content hashes and are naturally shared across forks (and can be deliberately reproduced for byte-identical commits such as template initial commits or empty commits with fixed metadata), a status webhook legitimately signed for one repository can update status rows belonging to a `Commit` in a completely different stack that happens to share the same SHA.

### Finding Description
The broken binding, stated explicitly: `Shipit::Commit#sha == params.sha` is treated as sufficient proof that `Shipit::Commit#stack.github_repo_name == payload['repository']['full_name']`. These are not equivalent — SHA equality is a property of git content, not of repository identity.

Code path:
- `Shipit::WebhooksController#create` dispatches to handlers after `verify_signature` [1](#0-0) .
- `verify_signature` resolves `Shipit.github(organization: repository_owner)` from the payload's `repository.owner.login` and checks the HMAC signature against that organization's configured GitHub App/webhook secret [2](#0-1) . This only proves the payload was genuinely emitted by GitHub for *some* repository owned by that organization/App installation — it says nothing about which repository's commits should be affected, and does nothing to disambiguate SHA collisions across different stacks/repos.
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 
This query is global across the entire `commits` table — it is not scoped by `stack_id`, and the payload's `repository` field (which names the sending repo) is read only to select the GitHub App for signature verification, never to filter which `Commit` rows get updated.
- `create_status_from_github!` mutates real state: it appends a `Status` row and re-derives `status`, which feeds `deployable?`, `blocked?`, and can trigger `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` [4](#0-3) [5](#0-4) .

Exploit flow: an attacker forks (or independently authors) a repository that shares an ancestor commit SHA with a victim stack's repository — either through ordinary forking (shared git history) or by deliberately constructing a byte-identical commit (fixed tree/parent/author/committer/timestamp, e.g., an empty template-initialization commit). The attacker installs/enables the (public) GitHub App on their own repo/org so that GitHub itself signs and sends a genuine `status` webhook for their own push, satisfying `verify_signature` with a completely legitimate signature for the attacker's own organization. `StatusHandler#process` then finds and updates every `Commit` row across every stack sharing that SHA, including the victim's, because the query has no repository/stack scoping.

None of the existing guards close this gap: `verify_signature` authenticates the sender's organization, not the SHA-to-repository binding; `drop_unhandled_event` only filters unrecognized event types; the `ExplicitParameters` schema in `StatusHandler.params` validates payload shape, not repository ownership; there is no `require_permission!`/`stacks` scope check inside `StatusHandler#process` at all.

### Impact Explanation
A payload that authenticates only for the attacker's own repository is able to mutate `Status` records — and therefore the computed deployability state — of a `Commit` belonging to an unrelated victim stack, purely because the SHA values match. This is a cross-tenant write: one repository's webhook traffic mutates another repository's commit/stack state without any authorization check tying the two together, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). If the affected commit is later relevant to deploy eligibility (e.g., `deployable?`, CI-gated auto-merge/continuous delivery via `schedule_continuous_delivery`), this can influence deploy/merge decisions for the victim stack based on forged status data.

### Likelihood Explanation
Exploitability is gated by a real precondition: the attacker must control a repository whose commit history shares a SHA with a commit already recorded in the victim's `commits` table, and must have (or be able to obtain) a GitHub App installation/webhook wired to Shipit for their own repository so that GitHub emits a genuinely, correctly-signed webhook. The former is trivial for shared ancestor commits between a fork and its upstream, or for deliberately reproduced fixed-content commits (empty commit with fixed author/committer/timestamp/parent, as called out in the question); the latter requires only that the attacker be permitted to install a public GitHub App on their own account/org, which is not a Shipit-privileged action. No Shipit secret, session, or API token is needed. The attack is repeatable against any stack whose recorded `Commit#sha` the attacker can reproduce or share via forking.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and analogous handlers) by the repository identified in the payload, not by `sha` alone — e.g., join through `Stack` and filter by `stack.repository_owner`/`stack.repository_name` matching `params.repository`, or restrict to commits belonging to stacks whose repo matches the payload's `repository.full_name` before applying `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook for repo A does not update commit status belonging to stack of repo B" do
  stack_a = shipit_stacks(:shipit) # repository "org-a/repo"
  stack_b = create_stack!(repository_name: 'repo', repository_owner: 'org-b') # unrelated repo

  shared_sha = 'deadbeef' * 5
  commit_a = stack_a.commits.create!(sha: shared_sha, message: 'shared ancestor')
  commit_b = stack_b.commits.create!(sha: shared_sha, message: 'shared ancestor')

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'org-b/repo', 'owner' => { 'login' => 'org-b' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.new.call(payload)

  commit_a.reload
  commit_b.reload

  # Equality claimed broken: commit.sha == params.sha does NOT imply
  # commit.stack.github_repo_name == payload['repository']['full_name']
  assert_equal 'success', commit_b.status.state # expected: legitimate update for org-b
  assert_equal 'success', commit_a.status.state # BUG: org-a's stack was mutated by org-b's webhook
end
```
This demonstrates that a single `StatusHandler` invocation naming only `org-b/repo` causes status writes on a `Commit` belonging to `stack_a` (a different repository/stack), confirming the unscoped `Commit.where(sha:)` cross-repository write.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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
