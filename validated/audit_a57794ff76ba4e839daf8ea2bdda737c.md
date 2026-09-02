### Title
Commit message forgery lets an attacker impersonate any existing Shipit user as a commit's `author` - (File: app/models/shipit/user.rb)

### Summary
`Shipit::User.find_or_create_author_from_github_commit` trusts a free-text `Merge-Requested-By: <login>` trailer taken verbatim from `github_commit.commit.message` and resolves/creates a `Shipit::User` for that login with no verification against the actual webhook sender, PR author, or commit committer identity. Any commit whose message contains that trailer for an existing user's login will have `Shipit::Commit#author` set to that user's record.

### Finding Description
The broken binding is: **claimed value (`match_info[1]` extracted from `commit.message` via `MergeRequest::MERGE_REQUEST_FIELD` regex) == actual authenticated identity of the commit's real author/requester** — this equality is never checked. [1](#0-0) 

The regex is anchored only to `MergeRequest::MERGE_REQUEST_FIELD = 'Merge-Requested-By'` [2](#0-1)  and matches any line of the free-text commit message body. `Commit.from_github` calls this method directly to set the persisted `author` association: [3](#0-2) 

Commits are ingested either through `PushHandler` → `stack.sync_github` → `GithubSyncJob#append_commit` → `Commit.create_from_github!` → `Commit.from_github`, or through `MergeRequest#find_or_create_commit_from_github_by_sha!`. In the push flow, the job fetches the actual commit objects from the GitHub API (`stack.github_commits`) rather than trusting webhook body content for the SHA/commit list, but the **commit message content itself** is whatever text is stored in the git history for that SHA on the tracked branch — this is attacker-controllable content if the attacker can get a commit bearing that message into the tracked branch (e.g., via a normal pull request that a maintainer merges, especially with GitHub's default squash-merge message which concatenates the PR's original commit messages verbatim unless manually edited).

No existing guard prevents this: `verify_signature`/`GitHubApp#verify_webhook_signature` only authenticate that the webhook came from GitHub, they say nothing about who authored the commit content within a legitimately-signed payload. `ExplicitParameters` on `PushHandler` only validates `ref`/`after` are present, not commit message content. There is no check anywhere in `User.find_or_create_author_from_github_commit` or `Commit.from_github` comparing the regex-extracted login against `params.sender.login`, the PR author, or the commit's actual GitHub `author`/`committer` field.

### Impact Explanation
Any commit whose message contains `Merge-Requested-By: <existing-login>` will have `Shipit::Commit#author` bound to that user's `Shipit::User` record instead of the real committer. This corrupts the attribution record on `Shipit::Commit`, which is surfaced in "deployed by"/"authored by" UI and used for `User#stacks_contributed_to` / `repositories_contributed_to` bookkeeping [4](#0-3) . This is an attribution/authorization-record spoofing issue affecting any repository whose branch commit history contains the forged trailer, for every existing Shipit user login (including privileged maintainers), and is repeatable per commit/PR. I could not confirm within this engine whether any deploy-authorization decision (as opposed to display/audit trail) is gated directly on `Commit#author`, so I cannot substantiate the "unauthorized deploy" claim from the question at Critical severity with the code reviewed; the confirmed, demonstrable impact is spoofed attribution/audit-trail data, not a demonstrated authorization bypass on deploy/merge actions.

### Likelihood Explanation
The attacker needs no Shipit credentials at all — only the ability to get a commit with a crafted message merged into a branch tracked by a Shipit stack (e.g., via a normal, unmodified pull request that a maintainer merges, particularly using GitHub's default squash-merge message which by default concatenates the source commits' messages). The target's GitHub login used in the forged trailer needs to be an existing Shipit user (`find_or_create_by_login!`), which is realistic since maintainer logins are public. This makes the attack cheap and repeatable across many repositories/stacks.

### Recommendation
Do not trust `Merge-Requested-By` from arbitrary commit message text as an identity assertion. Bind `author`/`merge_requested_by` only to identities obtained through an authenticated channel (e.g., the actual `MergeRequest#merge_requested_by`, set via `MergeRequest.request_merge!` from an authenticated Shipit session/API client, or the GitHub commit's own `author`/`committer` GitHub identity) and remove or ignore the free-text regex-based fallback in `Shipit::User.find_or_create_author_from_github_commit`.

### Proof of Concept
```ruby
# test/models/commits_test.rb (conceptual addition)
test '.create_from_github does not attribute a commit to an arbitrary user via a forged trailer' do
  victim = shipit_users(:walrus) # some existing, unrelated Shipit::User with a known login
  forged_message = "Fix bug\n\nMerge-Requested-By: #{victim.login}\n"
  github_commit = stub_github_commit(message: forged_message, author_login: 'attacker', committer_login: 'attacker')

  commit = Shipit::Commit.from_github(github_commit)

  # Binding under test: claimed login in commit message == actual authenticated actor
  refute_equal victim, commit.author, "commit.author must not be derived from unauthenticated commit-message text"
  assert_equal 'attacker', commit.author.login
end
```
This mirrors the existing `.create_from_github handle PRs merged by another Shipit stacks` test structure in `test/models/commits_test.rb`, asserting the divergence instead of the intended behavior.

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

**File:** app/models/shipit/user.rb (L84-94)
```ruby
    def repositories_contributed_to
      return [] unless id

      Stack.where(id: stacks_contributed_to).distinct.pluck(:repository_id)
    end

    def stacks_contributed_to
      return [] unless id

      Commit.where('author_id = :id or committer_id = :id', id:).distinct.pluck(:stack_id)
    end
```

**File:** app/models/shipit/merge_request.rb (L7-7)
```ruby
    MERGE_REQUEST_FIELD = 'Merge-Requested-By'
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
