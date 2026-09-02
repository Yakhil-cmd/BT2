### Title
Arbitrary commit-message trailer (`Merge-Requested-By: <login>`) lets any commit author impersonate an existing GitHub user as `Commit#author`, forging attribution later serialized into `deploy`/`rollback`/`merge` webhook payloads - (File: app/models/shipit/user.rb)

### Summary
`User.find_or_create_author_from_github_commit` trusts an unauthenticated, attacker-writable substring of the raw git commit message (`Merge-Requested-By: <login>`) to decide who the `Commit#author` is, instead of relying on the actual GitHub commit `author`/`committer` identity. Because `Commit#author` is later included in serialized objects (`until_commit`/`since_commit`) attached to `Hook.emit(:deploy, ...)` payloads delivered by `DeliverHookJob`, any commit that reaches this code path with a crafted trailer can attribute the resulting deploy/commit/merge webhook payload to an arbitrary existing (or newly created) Shipit `User`, who never authored, approved, or requested anything.

### Finding Description
The broken binding, stated explicitly:

`github_committer_identity_verified_by_webhook_HMAC(commit) == Commit#author.login`

is false whenever the commit message contains the trailer, because the code path ignores the real `commit.author`/`commit.commit.author` entirely in that case: [1](#0-0) 

```
def self.find_or_create_author_from_github_commit(github_commit)
  if (match_info = github_commit.commit.message.match(/^#{MergeRequest::MERGE_REQUEST_FIELD}: ([\w\-.]+)$/))
    ...
    return find_or_create_by_login!(match_info[1])
    ...
  end
  find_or_create_from_github(github_commit.author.presence || github_commit.commit.author.presence)
end
```

`find_or_create_by_login!` resolves purely on `login`, with no cross-check against `github_commit.author.id` / `github_commit.commit.author`: [2](#0-1) 

This trailer is intended for Shipit's own chatops merge flow, where `MergeRequest#merge_message` (`app/models/shipit/merge_request.rb:262-266`) embeds a *Shipit-verified* `merge_requested_by` login into a merge commit that Shipit itself creates through the GitHub API. The vulnerability is that `find_or_create_author_from_github_commit` cannot distinguish that trusted, Shipit-generated commit from any other commit reaching the same code path with an identical trailer string it never wrote — nothing checks the commit's real `committer`/`author` against the Shipit merge-bot identity before trusting the field.

Reachable path: a `push` webhook (`app/controllers/shipit/webhooks_controller.rb`) is HMAC-verified only over the whole payload (`verify_signature`) — it proves the payload came from the configured GitHub App/org, not that any particular commit body is trustworthy. `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb`) triggers `stack.sync_github`, which runs `GithubSyncJob#perform` → `fetch_missing_commits` (first-parent commits from GitHub's API) → `append_commit` → `stack.commits.create_from_github!(gh_commit)` → `Commit.from_github` → `User.find_or_create_author_from_github_commit`: [3](#0-2) [4](#0-3) 

This existing (and effectively demonstrated) behavior is confirmed by the repo's own test: [5](#0-4) 

which shows a commit whose real GitHub author fields are `"Shipit"` but whose message contains `"Merge-Requested-By: walrus\n"` results in `Commit.last.author == shipit_users(:walrus)`, regardless of who actually authored/pushed it.

Exploit flow: any first-parent commit landing on a Shipit-tracked branch — e.g. via a normal pull request merged with GitHub's native "Rebase and merge" or "Create a merge commit" strategy (which preserves the original committer's message verbatim, unlike Shipit's own chatops merge) — with a message ending in `Merge-Requested-By: victim_login` will be synced by `GithubSyncJob` and recorded with `author = victim_login`'s `User` record. If that user doesn't exist yet, `find_or_create_by_login!` creates a real `Shipit::User` for that GitHub login via `Shipit.github.api.user(login)`, meaning the attacker can even manufacture attribution to any real GitHub username. From there, `Commit#author` flows into any `Hook.emit(:deploy, ...)`/`:rollback`/`:commit`-style payload that serializes `until_commit`/`since_commit`, and `Hook.coerce_payload` / `Delivery#send!` / `DeliverHookJob#perform` deliver that forged attribution to every external webhook consumer.

None of the existing guards stop this: `verify_signature` only authenticates that GitHub sent the payload, not that any particular commit body is trustworthy; there is no check tying the trailer to Shipit's own merge-bot identity; `ExplicitParameters` on `PushHandler` only validates `ref`/`after` shape, not commit contents; and model validations on `User`/`Commit` don't validate provenance of the `author_id` assignment.

### Impact Explanation
An attacker who can get an arbitrary commit message onto a Shipit-tracked branch's first-parent history (via a normal PR merge using rebase/merge-commit strategies, not squash) can forge the `author` of that `Commit` to name any existing or resolvable GitHub login. This forged author is a permanent DB record and propagates into every subsequent webhook payload (`deploy`, `rollback`, `merge`, `commit_status`, etc.) referencing that commit via `Hook.emit` → `DeliverHookJob`, corrupting the audit trail external systems rely on to know "who deployed/approved this." This matches the Critical category "a record written for a repository that did not authenticate it" / forged authorization-audit trail in a delivered webhook.

### Likelihood Explanation
Requires: (1) a Shipit stack tracking the target repository/branch, and (2) the attacker's crafted commit message landing as a first-parent commit on that branch — typically via a normal, unprivileged pull-request contribution that a maintainer merges without a squash strategy. The attacker does not need push access to the branch, a Shipit session, or any secret; they only need a maintainer to merge their PR, which is an entirely ordinary contribution workflow that does not scrutinize trailing lines of commit messages. This is repeatable against any repository/stack configured this way and against any existing (or discoverable) GitHub login.

### Recommendation
Only trust the `Merge-Requested-By` trailer when the commit's actual GitHub author/committer matches Shipit's own merge-bot identity (e.g., the GitHub App/user Shipit uses to perform chatops merges), or better, stop deriving authorship from free-text commit message content entirely and instead pass the verified `merge_requested_by` user id through an out-of-band, non-spoofable channel (e.g., recorded on the `MergeRequest` record itself and looked up by PR/commit SHA rather than parsed from the message body).

### Proof of Concept
Minitest plan (extends the existing pattern in `test/models/commits_test.rb`):
```ruby
test '.create_from_github does not let an untrusted commit author impersonate victim_login' do
  victim = shipit_users(:walrus) # login: "walrus"

  attacker_commit = resource(
    sha: 'deadbeefcafebabefeed1234567890abcdef123',
    author: { id: 999999, login: 'attacker' },
    committer: { id: 999999, login: 'attacker' },
    commit: {
      author: { name: 'attacker', email: 'attacker@evil.example', date: Time.now },
      committer: { name: 'attacker', email: 'attacker@evil.example', date: Time.now },
      message: "totally normal feature\n\nMerge-Requested-By: walrus\n"
    }
  )

  @stack.commits.create_from_github!(attacker_commit)
  commit = Commit.last

  # BROKEN BINDING as asserted by the vulnerability:
  assert_equal victim, commit.author # author is "walrus" though attacker authored/pushed it

  # Forged attribution propagates into delivered webhook payload
  payload = Hook.coerce_payload(commit:)
  assert_includes payload, 'walrus'
end
```
This demonstrates the binding `github_authenticated_identity(commit) == Commit#author` fails: the real author/committer is `attacker`, yet `Commit#author.login == 'walrus'`, and that forged value is what gets serialized into the delivered hook payload.

### Citations

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

**File:** app/models/shipit/user.rb (L34-44)
```ruby
    def self.find_or_create_author_from_github_commit(github_commit)
      if (match_info = github_commit.commit.message.match(/^#{MergeRequest::MERGE_REQUEST_FIELD}: ([\w\-.]+)$/))
        begin
          return find_or_create_by_login!(match_info[1])
        rescue Octokit::NotFound
          # Corner case where the merge-requested-by user cannot be found (renamed/deleted).
          # In this case we carry on and search for the commit author
        end
      end
      find_or_create_from_github(github_commit.author.presence || github_commit.commit.author.presence)
    end
```

**File:** app/models/shipit/commit.rb (L105-125)
```ruby
    def self.from_github(commit)
      author = User.find_or_create_author_from_github_commit(commit)
      author ||= Anonymous.new
      committer = User.find_or_create_committer_from_github_commit(commit)
      committer ||= Anonymous.new

      record = new(
        sha: commit.sha,
        message: commit.commit.message,
        author:,
        committer:,
        committed_at: commit.commit.committer.date,
        authored_at: commit.commit.author.date,
        additions: commit.stats&.additions,
        deletions: commit.stats&.deletions
      )

      record.pull_request_head_sha = commit.parents.last.sha if record.pull_request?

      record
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L51-53)
```ruby
    def append_commit(gh_commit)
      stack.commits.create_from_github!(gh_commit)
    end
```

**File:** test/models/commits_test.rb (L106-132)
```ruby
    test '.create_from_github handle PRs merged by another Shipit stacks' do
      assert_difference -> { Commit.count }, +1 do
        @stack.commits.create_from_github!(
          resource(
            sha: '2adaad1ad30c235d3a6e7981dfc1742f7ecb1e85',
            author: {},
            committer: {},
            commit: {
              author: {
                name: 'Shipit',
                email: '',
                date: Time.now
              },
              committer: {
                name: 'Shipit',
                email: '',
                date: Time.now
              },
              message: "commit to trigger staging build\n\nMerge-Requested-By: walrus\n"
            }
          )
        )
      end

      commit = Commit.last
      assert_equal shipit_users(:walrus), commit.author
    end
```
