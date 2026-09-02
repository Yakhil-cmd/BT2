### Title
`PullRequest#github_pull_request=` binds authorship/assignment by GitHub login string alone, not `github_id` - ([File: app/models/shipit/pull_request.rb])

### Summary
`PullRequest#github_pull_request=` resolves `user`/`assignees` via `User.find_or_create_by_login!(login)`, which matches an existing `Shipit::User` row purely by the `login` column and only fetches/verifies `github_id` when creating a brand-new row. If GitHub's login-reuse behavior (after a rename) causes a webhook's `pull_request.user.login` (or `assignees[].login`) to collide with an existing, unrelated `User` row's stale `login`, Shipit will silently attribute the new PR to that pre-existing `User`, even though the underlying `github_id` differs.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:
`PullRequest#user.github_id == github_pull_request.user.id` (the actual GitHub account that authored the PR).

Code path:
- `app/models/shipit/pull_request.rb:44` — `self.user = User.find_or_create_by_login!(github_pull_request.user.login)`
- `app/models/shipit/pull_request.rb:45-47` — same for each assignee.
- `app/models/shipit/user.rb:22-28`:
```ruby
def self.find_or_create_by_login!(login)
  find_or_create_by!(login:) do |user|
    user.github_user = Shipit.github.api.user(login)
  end
end
```
`find_or_create_by!(login:)` first performs a lookup by `login` string alone (Rails' standard `find_or_create_by!` behavior: `find_by(login:) || create!(...)`). The block that populates `github_id`/name/email from the live GitHub API (`user.github_user = ...`) **only runs when a new record is created**. If a row with that `login` already exists, it is returned unchanged — its `github_id` is never checked, refreshed, or compared against the actual PR author's id.

Root cause: `login` is not a stable identity key on GitHub (usernames can be renamed and the freed name is claimable by any other account), but Shipit treats `login` as if it were, in this lookup path. Compare with `User.find_or_create_from_github` (`app/models/shipit/user.rb:46-58`), used elsewhere (e.g. commit author/committer resolution), which correctly keys off `github_id` via `find_from_github`/`find_by(github_id:)`. `find_or_create_by_login!` is the outlier that trusts the login string.

Exploit flow: a privileged Shipit `User` (e.g. an org member) renames their GitHub account, freeing their old login. An unprivileged attacker creates/renames a GitHub account to claim that freed login, then opens a pull request from their own fork against a repository Shipit tracks. GitHub's `pull_request.opened` webhook payload naturally reports `pull_request.user.login` = the reused login string, with a different, attacker-controlled `github_id`/`id`. `OpenedHandler` (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`) validates the payload schema (login is just a `String`) and dispatches to `ReviewStackAdapter#create!`, which calls `PullRequest#github_pull_request=`, hitting `find_or_create_by_login!` and binding the attacker's PR to the pre-existing privileged `User` row.

Existing guards do not prevent this: webhook signature verification (`GitHubApp#verify_webhook_signature`) only proves the payload came from GitHub, not that login-to-identity mapping is stable; `ExplicitParameters` only validates shape/types, not identity; there is no `github_id` cross-check anywhere in this call path. This is a genuine, narrow edge case tied to GitHub's login-reuse semantics rather than an arbitrary "attacker names any field" bug — it requires the specific precondition of a freed/reused login, which the question explicitly frames as the trigger mechanism. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
The direct, demonstrable effect is data attribution corruption: `Shipit::PullRequest#user`/`#assignees` (and by extension `stack.pull_requests`) point to the wrong `User` row — one belonging to a different real GitHub identity than the PR's actual author. This is scoped to record attribution within the engine's own database, not to `Command`/`PTY.spawn` execution, credential exfiltration, or an unauthorized merge/deploy being triggered by this code path alone: I could not find any code that uses `PullRequest#user`/`#assignees` to grant `authorized?`, bypass `require_permission!`, or feed the merge-queue decision (`MergeRequest.request_merge!` sources its `merge_requested_by` from `current_user`/session — an authenticated Shipit user — not from `PullRequest#user`). So while the binding is genuinely broken, the "cross-repository trust decision" impact asserted in the question is not substantiated by a traceable path from `PullRequest#user`/`#assignees` into merge/deploy authorization logic in this codebase; those fields appear used for display/attribution (`identifiers_for_ping`, UI, hooks) rather than as an authorization gate. [4](#0-3) 

### Likelihood Explanation
Requires a specific, low-frequency GitHub-side precondition: a previously known/privileged GitHub account must rename itself, freeing its login, and a different account must claim that exact login before or while opening a PR — this is not attacker-controlled at will and depends on GitHub's account-rename/username-availability behavior, which Shipit has no control over. `review_stacks_enabled` and a matching provisioning policy must also be active on the repository for `OpenedHandler` to act. This is a real but low-probability, hard-to-target edge case, not a repeatable attack an adversary can trigger against an arbitrary repository/stack on demand.

### Recommendation
Change `User.find_or_create_by_login!` (or add a `find_or_create_by_login_and_id!` used from `PullRequest#github_pull_request=`) to key primarily on `github_id`, using `login` only as a display/lookup hint, mirroring `User.find_or_create_from_github`. Concretely: pass the full `github_pull_request.user` (with `.id`) instead of just `.login`, look up `find_by(github_id:)` first, and if a `login`-only match is found with a mismatched `github_id`, either update that row's identity fields (if truly the same person, i.e., `github_id` unchanged) or create/attach a distinct `User` row for the new `github_id`.

### Proof of Concept
Under `test/models/shipit/pull_request_test.rb` (not modifying `test/**` in place, but as a plan for a proof):
1. Create an existing `Shipit::User` fixture/row with `login: "shared_login"`, `github_id: 111`.
2. Stub a `github_pull_request` resource whose `user.login == "shared_login"` and `user.id == 222` (a different `github_id`), plus required `head`, `assignees: []`, `labels: []`.
3. Call `pull_request.github_pull_request = stubbed_pr`.
4. Assert the broken binding: `assert_equal 111, pull_request.user.github_id` will pass today (returns the old privileged user) while `assert_not_equal 222, pull_request.user.github_id` also passes — demonstrating `pull_request.user.github_id != github_pull_request.user.id`, i.e., the PR is bound to the wrong GitHub identity purely via login collision. [1](#0-0)

### Citations

**File:** app/models/shipit/pull_request.rb (L36-47)
```ruby
    def github_pull_request=(github_pull_request)
      self.github_id = github_pull_request.id
      self.number = github_pull_request.number
      self.api_url = github_pull_request.url
      self.title = github_pull_request.title
      self.state = github_pull_request.state
      self.additions = github_pull_request.additions
      self.deletions = github_pull_request.deletions
      self.user = User.find_or_create_by_login!(github_pull_request.user.login)
      self.assignees = github_pull_request.assignees.map do |github_user|
        User.find_or_create_by_login!(github_user.login)
      end
```

**File:** app/models/shipit/user.rb (L22-28)
```ruby
    def self.find_or_create_by_login!(login)
      find_or_create_by!(login:) do |user|
        # Users are global, any app can be used
        # This will not work for users that only exist in an Enterprise install
        user.github_user = Shipit.github.api.user(login)
      end
    end
```

**File:** app/models/shipit/user.rb (L46-58)
```ruby
    def self.find_or_create_from_github(github_user)
      find_from_github(github_user) || create_from_github(github_user)
    end

    def self.find_from_github(github_user)
      return unless github_user.id

      find_by(github_id: github_user.id)
    end

    def self.create_from_github(github_user)
      create(github_user:)
    end
```

**File:** app/models/shipit/merge_request.rb (L126-143)
```ruby
    def self.request_merge!(stack, number, user)
      now = Time.now.utc
      merge_request = begin
        create_with(
          merge_requested_at: now,
          merge_requested_by: user.presence
        ).find_or_create_by!(
          stack:,
          number:
        )
      rescue ActiveRecord::RecordNotUnique
        retry
      end
      merge_request.update!(merge_requested_by: user.presence)
      merge_request.retry! if merge_request.rejected? || merge_request.canceled? || merge_request.revalidating?
      merge_request.schedule_refresh!
      merge_request
    end
```
