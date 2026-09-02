This confirms the vulnerability. The critical code is in `User.find_or_create_author_from_github_commit`:

```ruby
def self.find_or_create_author_from_github_commit(github_commit)
  if (match_info = github_commit.commit.message.match(/^#{MergeRequest::MERGE_REQUEST_FIELD}: ([\w\-.]+)$/))
    begin
      return find_or_create_by_login!(match_info[1])
    rescue Octokit::NotFound
    end
  end
  find_or_create_from_github(github_commit.author.presence || github_commit.commit.author.presence)
end
``` [1](#0-0) 

This directly parses `Merge-Requested-By: <login>` from the raw commit message text — with no check that the commit actually came from a Shipit-initiated merge, no check that a corresponding `MergeRequest` record exists, and no relation to the real GitHub commit author/committer. This is distinct from `Commit#identify_merge_request`, which only sets `author` from `merge_request.merge_requested_by` when an existing `MergeRequest` record (created via `MergeRequest.request_merge!`, an authenticated in-app action) matches the PR number [2](#0-1)  — that path is safe. The vulnerable path bypasses it entirely by regex-matching the commit message body itself.

### Title
Commit message `Merge-Requested-By:` forges deploy author identity - (File: app/models/shipit/user.rb)

### Summary
`User.find_or_create_author_from_github_commit` trusts a `Merge-Requested-By: <login>` string embedded anywhere in a GitHub commit message to assign commit authorship, with no verification that the commit originated from Shipit's own merge-queue flow or that the named user actually authored/committed the change.

### Finding Description
Broken binding: `Commit#author.login` should equal the GitHub identity that actually authored/committed the commit (`github_commit.author.login` / `github_commit.commit.author`), but instead can equal an arbitrary attacker-chosen string extracted from `github_commit.commit.message` via `find_or_create_author_from_github_commit`.

Path: attacker pushes a commit with message containing `Merge-Requested-By: victim` to a branch on a repository they administer, with `continuous_deployment: true` configured for that stack. The correctly-signed push webhook (real, since it's their own repo) triggers `GithubSyncJob#perform` → `fetch_missing_commits` (`app/jobs/shipit/github_sync_job.rb:26,55-69`) → `append_commit` → `Commit.create_from_github!` → `Commit.from_github` (`app/models/shipit/commit.rb:105-125`) → `User.find_or_create_author_from_github_commit` (`app/models/shipit/user.rb:34-44`). The regex `/^Merge-Requested-By: ([\w\-.]+)$/` matches the attacker's forged line and calls `find_or_create_by_login!(match_info[1])`, creating or reusing a `User` record for the victim's GitHub login and setting it as `Commit#author` — with no relationship whatsoever to a real `MergeRequest` record or Shipit-mediated merge. This value later flows into `Task#user`/`Task#author` and is exposed as `GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL`/`SHIPIT_USER` in `TaskCommands#env` (`lib/shipit/task_commands.rb:37,43-44`) during deploy.

Existing guards do not stop this: webhook signature verification only proves the push came from the attacker's own (legitimately owned) repository — it says nothing about commit message content; `Commit#identify_merge_request`'s legitimate `merge_request.merge_requested_by` binding is a separate, safe code path that is not what's exploited here; there is no validation anywhere that the `Merge-Requested-By` field in a commit message corresponds to an actual `MergeRequest.merge_requested_by` set by `MergeRequest.request_merge!`.

### Impact Explanation
Any commit ingested through `GithubSyncJob` (not limited to Shipit-generated merge commits) can have its recorded `author`/associated `User` forged to any existing GitHub login (or a new one auto-created via `find_or_create_by_login!`, which calls the GitHub API to fetch that user's public profile). Once deployed via `continuous_deployment: true`, the victim's name/email appear in `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, and `SHIPIT_USER` env vars for the deploy task, in deploy notifications, and potentially in git commits made by deploy scripts — falsely attributing actions/deploys to the victim. This is repeatable per push and works against any repository the attacker administers that Shipit tracks with `continuous_deployment: true`; it does not cross into other tenants' repos or grant code execution/secret exfiltration, so it best matches identity-attribution/logging integrity impact rather than the Critical categories listed (RCE, auth bypass, secret exfiltration, cross-stack mutation, unauthorized deploy/rollback/merge) since the deploy itself is authorized by the (attacker-owned) repo's own continuous_deployment configuration — the deploy already occurs regardless of forged authorship.

### Likelihood Explanation
Low cost, no privileges beyond controlling a repo already onboarded to Shipit with `continuous_deployment: true` — the attacker must administer/push to that tracked repo, which the threat model grants ("repository they administer"). No branch protection is required to block it since ordinary pushes reach `GithubSyncJob` regardless. Fully repeatable and requires no secrets.

### Recommendation
In `User.find_or_create_author_from_github_commit`, only honor the `Merge-Requested-By` field when it corresponds to a `MergeRequest` record for the stack whose `merge_requested_by` was set via the authenticated `MergeRequest.request_merge!`/merge-queue flow, matching by PR number as `Commit#identify_merge_request` already does — remove the raw commit-message regex fallback that trusts arbitrary commit text.

### Proof of Concept
minitest under `test/models/users_test.rb` (or `test/jobs/github_sync_job_test.rb`):
1. Create a `Stack` with `continuous_deployment: true`.
2. Create a victim `Shipit::User` with `login: 'victim'`, `name: 'Victim Name'`.
3. Stub a GitHub commit response object whose `commit.message` is `"Some commit\n\nMerge-Requested-By: victim\n"` and whose real `author`/`commit.author` corresponds to the attacker's own GitHub identity (different login).
4. Call `Shipit::Commit.from_github(stubbed_commit)` (or run `GithubSyncJob` end-to-end with the iterator stubbed).
5. Assert `commit.author.login == 'victim'` even though `stubbed_commit.author.login == 'attacker'` — proving `Commit#author.login` does NOT equal `github_commit.author.login` (the binding is broken).
6. Optionally continue: create a `Task`/`Deploy` for that commit, instantiate `Shipit::TaskCommands.new(task)`, and assert `env['GIT_COMMITTER_NAME'] == 'Victim Name'` per `lib/shipit/task_commands.rb:43`, despite the victim never pushing or authenticating.

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

**File:** app/models/shipit/commit.rb (L316-328)
```ruby
    def identify_merge_request
      return unless message_parser.pull_request?

      if merge_request = stack.merge_requests.find_by(number: message_parser.pull_request_number)
        self.merge_request = merge_request
        self.pull_request_number = merge_request.number
        self.pull_request_title = merge_request.title
        self.author = merge_request.merge_requested_by if merge_request.merge_requested_by
      end

      self.pull_request_number = message_parser.pull_request_number unless self[:pull_request_number]
      self.pull_request_title = message_parser.pull_request_title unless self[:pull_request_title]
    end
```
