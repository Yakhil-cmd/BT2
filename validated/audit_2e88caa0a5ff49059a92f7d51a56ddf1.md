### Title
Cross-repository status forgery via unscoped SHA lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits solely by `sha`, with no repository or stack scoping, so a `status` webhook signed by *any* GitHub organization can write a `Status` (e.g. `context: shipit/checks`, `state: failure`) onto every `Commit` row across every stack that happens to share that SHA. This lets an attacker who controls one tracked repository flip the deployability/merge eligibility of a completely unrelated victim stack's commit.

### Finding Description
The broken invariant, stated as an equality that should hold but doesn't:

`Status written for sha S` should imply `Status.stack_id == stack_that_authenticated_the_webhook_for_sha_S`.

In practice: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [1](#0-0)  writes to *every* `Commit` row matching that SHA, regardless of which `stack_id`/repository the row belongs to.

Path traced:
1. `WebhooksController#create` parses the raw JSON and dispatches by `X-Github-Event` to registered handlers, with `verify_signature` only checking that the payload was HMAC-signed with the webhook secret configured for the organization named in `params['repository']['owner']['login']` — i.e., the org of the repo that *sent* the event [2](#0-1) [3](#0-2) . This check validates provenance ("this came from GitHub for org X"), it does not validate that the `sha`, `context`, or `state` fields belong to org X's repositories only.
2. `StatusHandler` only requires `sha`, `state`, and optional `context`; it never reads or checks `params['repository']` [4](#0-3) .
3. `Commit.create_status_from_github!` → `add_status` → `statuses.replicate_from_github!(stack_id, github_status)` uses the `Commit`'s *own* `stack_id`, not any ID from the payload [5](#0-4) [6](#0-5) , so the resulting `Status` is genuinely attached to whichever stack that `Commit` row belongs to — including a victim stack the attacker never touched.
4. `add_status` then recomputes `status`, fires `deployable_status`/`commit_status` hooks, and calls `stack.schedule_merges` — i.e. the victim stack's deployability and merge pipeline is directly affected by this cross-tenant write [7](#0-6) .

Exploit flow: An attacker who administers/pushes to their own GitHub repo tracked by Shipit (fully unprivileged w.r.t. the victim) can produce a commit whose SHA matches a commit already recorded (as a `Commit` row) in a victim stack — this is routine when repos share history (forks, common upstream commits, cherry-picks, monorepo splits) since git SHAs are content-addressed and identical across repos for identical commit content. The attacker then sets a `status` on that SHA in their own repo (via the GitHub Status API, using their own token/CI, fully within their rights over their own repo) with `context: shipit/checks`, `state: failure`. GitHub delivers a `status` webhook to Shipit, correctly signed with the attacker's own org's webhook secret. `verify_signature` passes (it only checks that org X really sent this event), and `StatusHandler#process` then writes that `failure` status onto **every** `Commit` row with that SHA — including the victim's, in a stack the attacker's org never authenticated against.

Existing guards fail because: `verify_signature` authenticates the *sender org*, not the *scope of records mutated*; `ExplicitParameters` only validates payload shape, not repository ownership; there is no `stack_id`/`repository` filter anywhere in `StatusHandler` or in `Commit.create_status_from_github!`.

### Impact Explanation
A `status` webhook legitimately signed by one organization's repository mutates `Status`/`Commit` state belonging to an entirely different stack/repository/tenant. If `shipit/checks` is in the victim stack's `ci.require`, a forged `failure` immediately flips `deployable?` to false, blocking legitimate deploys, or — depending on the transition (`unknown`/`pending` → any state) — fires `deployable_status`/`commit_status` hooks and can trigger `stack.schedule_merges`, altering automatic merge behavior on the victim's commit. This is repeatable against any stack whose tracked commits share a SHA with a repo the attacker controls, and matches the Critical category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions are modest: the attacker needs write/administrative access to at least one repository that is tracked by Shipit (a very low bar — could be their own fork, a repo they maintain, or any tenant onboarded to the same Shipit instance), and a SHA collision with the victim's tracked commit, which arises naturally in forks, shared upstream history, or cherry-picked commits — no cryptographic hash collision is required, only identical commit content. No secrets, sessions, or elevated Shipit roles are needed; the webhook signature check is satisfied honestly by GitHub for the attacker's own org. The attack is repeatable at will against any stack sharing history with the attacker's repo.

### Recommendation
Scope `StatusHandler#process` (and the analogous check-run/other SHA-keyed handlers) to only update `Commit` rows belonging to stacks whose repository matches `params['repository']['full_name']` (cross-referenced via `Stack#repository`), e.g. `Commit.joins(:stack).merge(Stack.where(repository: repository_from_payload)).where(sha: params.sha)`, rejecting or ignoring updates for commits in unrelated repositories.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":status webhook from attacker repo mutates commit in unrelated victim stack sharing sha" do
  victim_stack = shipit_stacks(:shipit) # requires "shipit/checks" via ci.require
  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared ancestor")

  before_state = victim_commit.reload.state
  assert_not_equal "failure", before_state

  request.headers['X-Github-Event'] = 'status'
  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'failure',
    'context' => 'shipit/checks',
    'repository' => { 'owner' => { 'login' => 'attacker-org' }, 'full_name' => 'attacker-org/unrelated-repo' }
  }
  GitHubApp.any_instance.stubs(:verify_webhook_signature).returns(true) # simulates a genuinely-signed attacker webhook

  post :create, body: attacker_payload.to_json, as: :json

  victim_commit.reload
  assert_equal "failure", victim_commit.state          # victim's commit state was mutated
  refute victim_commit.deployable?                      # victim's deployability flipped
  assert_equal 1, victim_commit.statuses.where(context: 'shipit/checks', state: 'failure').count
end
```
This demonstrates the equality `Status.stack_id == authenticated_stack.id` is violated: the `Status` row created belongs to `victim_stack`, even though only `attacker-org` authenticated the webhook.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
