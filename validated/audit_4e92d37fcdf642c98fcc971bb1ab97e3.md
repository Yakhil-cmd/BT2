### Title
Cross-tenant status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit purely by `Commit.where(sha: params.sha)`, with no constraint tying the lookup to the repository/organization that authenticated the webhook. An attacker who controls any org registered in the Shipit instance (and thus knows that org's `webhook_secret`) can pass signature verification and then supply an arbitrary `sha` string copied from a public commit page of an unrelated Org A repository, causing Shipit to write a fabricated CI status onto Org A's commit.

### Finding Description
The broken binding: `knows(sha_string_of_org_A_commit)` (public information, no relationship required) `== authorized_to_mutate(org_A_commit.statuses)`. This is false — knowing a 40-character hex string published on a public GitHub commit page grants zero authority over that repository.

Path:
1. `Shipit::WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and validates the HMAC signature against `Shipit.github(organization: repository_owner)`'s webhook secret [2](#0-1) . This only proves the attacker knows the secret of *the org they name in `repository.owner.login`* — an org they legitimately control. It says nothing about the `sha` field's origin.
2. `Shipit::Webhooks::Handlers::StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 
This query is global across the entire `commits` table — it is not scoped through `Repository.from_github_repo_name(repository_name)` the way sibling handlers do it. Contrast with `CheckSuiteHandler`, which scopes through `stacks.where(branch: ...)` before touching `stack.commits` [4](#0-3) , and `PushHandler`, which scopes via `stacks.not_archived.where(branch:)` [5](#0-4) . Both derive `stacks` from `Repository.from_github_repo_name(repository_name)` in the shared `Handler` base class [6](#0-5) . `StatusHandler` never calls `stacks` or filters by `repository_name` at all.

`create_status_from_github!` then mutates the resolved commit unconditionally: `statuses.replicate_from_github!(stack_id, github_status)` [7](#0-6) , writing a real `Status` row tied to Org A's `stack_id` and commit.

The contrasted job path, `RefreshStatusesJob`, is correctly scoped: it resolves the commit by internal Shipit primary key (`Commit.find(params[:commit_id])`) rather than by attacker-supplied sha string, and that job is only ever enqueued internally (`schedule_refresh_statuses!` / stack-triggered refresh), never directly from unauthenticated webhook input [8](#0-7) . So the job itself is not exploitable this way — the vulnerability is specific to the direct webhook path in `StatusHandler`.

No other guard closes the gap: `ExplicitParameters` only validates types/presence of `sha`/`state`/etc, not repository ownership; `drop_unhandled_event` only checks the event type is registered; `verify_signature` authenticates *an* org, not *the* org owning the target commit.

### Impact Explanation
Any attacker who legitimately owns/controls one org configured in the Shipit instance (satisfying `verify_signature` with their own secret) can write arbitrary CI status records (`success`, `failure`, `pending`, with attacker-chosen `description`/`target_url`/`context`) onto any commit in any other tenant's repository, as long as they know that commit's sha (trivially public on GitHub). If that stack has `continuous_deployment` enabled, forging a `success` status on an existing commit can trigger an actual deploy pipeline transition for Org A (status changes feed into deploy-readiness / CD checks elsewhere in the codebase), making this a payload from one tenant mutating another tenant's stack/commit state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is fully repeatable against any commit sha in any tenant's history, at will, with no persistence of secrets needed beyond the attacker's own org.

### Likelihood Explanation
Preconditions are low-cost: the attacker needs (a) their own org/repo already registered in this Shipit instance with a working `webhook_secret` (something any legitimate but unprivileged customer/org owner of the multi-tenant Shipit install would have), and (b) any public sha from Org A's GitHub repo, obtainable via any public commit URL. No GitHub push, no shared git history, no Shipit session, and no privileged role are required. The only engineering effort is crafting one JSON POST with a valid signature over the raw body using their known secret.

### Recommendation
Scope `StatusHandler#process` to the repository asserted by the webhook payload, mirroring `PushHandler`/`CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
where `stacks` resolves via `Repository.from_github_repo_name(repository_name)` (already provided by the `Handler` base class), so a commit can only receive a status update from a webhook whose `repository.full_name` matches the commit's own stack/repository.

### Proof of Concept
Minitest plan (webhooks controller test, e.g. extending `test/controllers/webhooks_controller_test.rb` style):
```ruby
test ":status from Org B cannot mutate Org A's commit by reusing its sha" do
  org_a_commit = shipit_commits(:first) # belongs to stack/repo A
  org_a_sha = org_a_commit.sha

  # Craft a status payload claiming to be from an unrelated repository (Org B),
  # but reusing Org A's public sha.
  forged_payload = {
    'sha' => org_a_sha,
    'state' => 'success',
    'description' => 'forged',
    'context' => 'attacker/ci',
    'repository' => { 'full_name' => 'org-b/unrelated-repo', 'owner' => { 'login' => 'org-b' } }
  }.to_json

  # Signature computed with Org B's own (attacker-known) webhook_secret,
  # satisfying `verify_signature` for repository_owner == 'org-b'.
  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', org_b_webhook_secret, forged_payload)

  request.headers['X-Github-Event'] = 'status'
  request.headers['X-Hub-Signature'] = signature

  assert_difference -> { org_a_commit.statuses.count }, 0 do
    post :create, body: forged_payload, as: :json
  end
  # Assertion above SHOULD hold (no mutation) after the fix.
  # Before the fix, this assertion fails: org_a_commit.statuses.count increases by 1,
  # proving Org B forged a status onto Org A's commit despite repository.full_name mismatch.
end
```
Equality checked: `payload['repository']['full_name'] == org_a_commit.stack.github_repo_name` is **false** both before and after the fix, but only after the fix does that mismatch prevent the status write; before the fix, `Commit.where(sha: params.sha)` ignores the mismatch entirely and mutates Org A's commit.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/jobs/shipit/refresh_statuses_job.rb (L7-14)
```ruby
    def perform(params)
      if params[:commit_id]
        Commit.find(params[:commit_id]).refresh_statuses!
      else
        stack = Stack.find(params[:stack_id])
        stack.commits.order(id: :desc).limit(30).each(&:refresh_statuses!)
      end
    end
```
