### Title
Attacker-controlled commit message trailer `Merge-Requested-By: <login>` lets a forked-repo commit forge `Commit#author` to an arbitrary existing Shipit user - ([File: app/models/shipit/user.rb])

### Summary
`User.find_or_create_author_from_github_commit` trusts a free-text trailer inside the raw commit message body (`Merge-Requested-By: <login>`) to decide commit authorship, instead of relying on the verified GitHub author identity or Shipit's own `MergeRequest#merge_requested_by` record. Because this trailer is just text inside a commit that a PR author fully controls, and because `GithubSyncJob`/`Commit.from_github` processes *any* commit that lands in the tracked branch's first-parent history (not only Shipit-generated merge commits), an attacker can get a commit attributed to an arbitrary existing Shipit login instead of themselves.

### Finding Description
The broken binding: for a given `Commit` row, GitHub's API says `commit.commit.author.login == "attacker"` (or whatever the actual committer is), but Shipit writes `Commit#author_id == User.find_by(login: "admin-login").id`.

Code path:
- [1](#0-0)  — `find_or_create_author_from_github_commit` regex-matches `github_commit.commit.message` against `/^Merge-Requested-By: ([\w\-.]+)$/` and, on match, unconditionally calls `find_or_create_by_login!(match_info[1])`, returning that user as the commit's author with no check that this login corresponds to who actually requested/performed the merge.
- [2](#0-1)  — `Commit.from_github` calls this method to set `author:` when building a `Commit` record from a `github_commit`.
- [3](#0-2)  and start="55" end="69" — `GithubSyncJob#append_commit` calls `stack.commits.create_from_github!(gh_commit)` for every commit discovered via `FirstParentCommitsIterator` walking the tracked branch, regardless of how that commit reached the branch (Shipit-driven merge queue merge, GitHub UI merge, rebase merge, or even a maintainer manually merging a PR outside of Shipit).

Root cause: the trailer is intended to record the person who *legitimately* requested a Shipit-driven merge (written by Shipit itself via `MergeRequest#merge_message`, [4](#0-3) , when Shipit performs the merge through `merge!`). But `find_or_create_author_from_github_commit` cannot distinguish a commit message written by Shipit's own merge flow from one written by an attacker. Any commit whose raw message body contains a line matching that exact pattern — including a commit authored entirely by the attacker in their own fork/PR — will have its author forged to the named login when that commit is synced (e.g. via a rebase merge that preserves the original commit as-is in the base branch's first-parent history, or a maintainer copy-pasting/typing such a line into a squash/merge commit message on GitHub's UI). No signature verification, `ExplicitParameters` schema, or authorization check anywhere in this path validates the trailer's target login against the actual merge initiator; `verify_signature`/webhook auth only gates whether GitHub's payload is accepted, not the semantic content of a commit message.

### Impact Explanation
Successful exploitation forges the `author_id` column of a `Commit` row for the targeted stack, attributing an attacker's commit to any existing Shipit user (e.g., a maintainer or admin login) purely from message content the attacker controls. This is used in git blame/audit trails, deployment descriptions (`author: task.author.login` in `CommitDeploymentStatus#description`), `merge_request.merge_requested_by`-style provenance tracking, and rollback/lock attribution (`lock_author`) shown in `test/models/rollbacks_test.rb`. It undermines the integrity of "who did this" records across the stack and could be used to implicate an innocent maintainer for a malicious change, or to make a hostile commit appear to have been sanctioned by a trusted user in the UI/audit trail — a repeatable, per-repository forgery requiring no privileges. It does not by itself grant deploy/RCE capability (deploy triggering is separate and requires `require_permission :deploy` gating in `DeploysController`), so this falls short of the Critical bar (no forged webhook/session/token acceptance, no secret exfiltration, no cross-repository mutation, no unauthorized deploy/rollback/merge is directly triggered by this alone).

### Likelihood Explanation
The precondition that a raw attacker-authored commit message (not a synthesized merge/squash message) ends up verbatim in the tracked branch's first-parent history depends on the base repository's merge configuration (e.g., rebase-merge enabled, or manual merges outside Shipit's merge queue) — this is plausible on many real-world GitHub configurations but not guaranteed, and out of the attacker's direct control (they don't choose the merge strategy). The attacker's own cost is minimal (craft a commit message), but achieving the exact reachable path (their raw message becoming part of first-parent history) requires either the repo to allow rebase merges of external PRs or a maintainer to preserve/paste the trailer text when merging — a moderate, config-dependent likelihood rather than a trivial one-shot exploit against any Shipit-managed repo.

### Recommendation
Do not trust arbitrary commit-message text to assign authorship. Only honor `Merge-Requested-By` when the commit is verified to be the actual merge commit created by Shipit's own `MergeRequest#merge!` (e.g., match it against `stack.merge_requests` by SHA/PR number, similar to how `identify_merge_request` already resolves `merge_request.merge_requested_by` via `stack.merge_requests.find_by(number: ...)` in `app/models/shipit/commit.rb`), rather than regex-matching the raw message body of every synced commit.

### Proof of Concept
```ruby
# test/models/commits_test.rb
test "author is not forged from a commit message trailer written by an attacker" do
  stub_request(:get, %r{api.github.com/users/admin-login})
    .to_return(status: 200, body: { id: 999, login: 'admin-login' }.to_json)

  github_commit = stub(
    sha: 'deadbeef',
    commit: stub(
      message: "evil change\n\nMerge-Requested-By: admin-login\n",
      author: stub(date: Time.now, name: 'attacker', email: 'attacker@evil.test', login: 'attacker'),
      committer: stub(date: Time.now)
    ),
    author: stub(id: 1234, login: 'attacker', presence: stub(id: 1234, login: 'attacker')),
    committer: stub(presence: nil),
    stats: nil,
    parents: []
  )

  commit = Shipit::Commit.create_from_github!(github_commit)

  # Broken binding demonstrated: GitHub says author login == 'attacker',
  # but Shipit records author login == 'admin-login'.
  assert_equal 'attacker', github_commit.commit.author.login
  assert_equal 'admin-login', commit.author.login # currently forged; should be 'attacker'
end
```
This shows the divergence: the GitHub API's actual commit author (`attacker`) does not match the `author_id` persisted on the `Commit` row (`admin-login`), confirming the forgery is reproducible without any live GitHub access or elevated privileges.

### Citations

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

**File:** app/models/shipit/commit.rb (L105-120)
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
```

**File:** app/jobs/shipit/github_sync_job.rb (L51-53)
```ruby
    def append_commit(gh_commit)
      stack.commits.create_from_github!(gh_commit)
    end
```

**File:** app/models/shipit/merge_request.rb (L262-266)
```ruby
    def merge_message
      return title unless merge_requested_by

      "#{title}\n\n#{MERGE_REQUEST_FIELD}: #{merge_requested_by.login}\n"
    end
```
