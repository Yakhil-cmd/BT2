### Title
Attacker-controlled commit message overrides `Commit#author` via forged `Merge-Requested-By` field - (File: app/models/shipit/user.rb)

### Summary
`Shipit::User.find_or_create_author_from_github_commit` trusts the free-text `Merge-Requested-By: <login>` line inside a commit message to determine `Commit#author`, without verifying that the string actually corresponds to a real merge request made by that user or to the GitHub-reported commit author. Any external contributor who can get a commit with a forged message into a tracked stack (via a plain push to a tracked branch, or via a pull request that Shipit syncs/fetches) can make Shipit attribute that commit to an arbitrary existing Shipit user login.

### Finding Description
The broken binding: `Commit#author` should equal the actual GitHub identity that authored/committed the payload, i.e. `commit.author` (GitHub API author) — but instead it can be forced to equal an attacker-chosen string embedded in `commit.commit.message`.

Code path:
- `Shipit::Commit.from_github` calls `User.find_or_create_author_from_github_commit(commit)` [1](#0-0) .
- `find_or_create_author_from_github_commit` matches `github_commit.commit.message` against `/^#{MergeRequest::MERGE_REQUEST_FIELD}: ([\w\-.]+)$/` and, on match, calls `User.find_or_create_by_login!(match_info[1])`, entirely bypassing the actual GitHub commit author (`github_commit.author`) [2](#0-1) .
- `MergeRequest::MERGE_REQUEST_FIELD` is just the literal string `'Merge-Requested-By'` [3](#0-2) , and this string is normally written by Shipit itself into the *merge commit message* it hands to GitHub during `MergeRequest#merge!` [4](#0-3) . Nothing about the regex ties it to Shipit's own merge action — it matches any commit message containing that line, from any source (a directly authored/pushed commit, a rebase, a forged commit crafted by the attacker locally and pushed to their own branch/fork).
- Commits reach `Commit.from_github`/`create_from_github!` through two unprivileged-adjacent paths:
  - `GithubSyncJob#append_commit` → `stack.commits.create_from_github!(gh_commit)` for commits fetched along the tracked branch [5](#0-4) .
  - `MergeRequest#find_or_create_commit_from_github_by_sha!`, invoked from `github_pull_request=` when a tracked PR's head/base commit is fetched and stored as a detached commit [6](#0-5) , [7](#0-6) .

Attacker request: open a pull request (or push to a branch that ends up as the PR head) whose commit message body contains a line `Merge-Requested-By: victim-login` where `victim-login` is an existing, privileged Shipit user's GitHub login. No Shipit credentials, webhook secret, or GitHub App key are needed — the attacker only needs the ability to author a commit and have GitHub emit the corresponding webhook (pull_request opened, or push, depending on which path is enabled on the target stack/repo).

Existing guards do not stop this: webhook signature verification (`GitHubApp#verify_webhook_signature`) only confirms the *request* came from GitHub, not that the *commit message contents* are trustworthy — GitHub happily relays whatever commit message the attacker wrote. `force_github_authentication`, `User#authorized?`, and `require_permission!` govern who can *act as* a Shipit user in the UI/API; they are never consulted when a commit is ingested from GitHub. No repository/stack model validation inspects commit-message-derived author fields.

### Impact Explanation
Successful exploitation causes `Commit#author` for an attacker-supplied commit to be set to an arbitrary existing Shipit user (the "victim"), rather than the real GitHub author. This corrupts commit-authorship data used across the UI (author name/link rendered on commit/deploy/task views) and any downstream logic keyed off `Commit#author`/`stacks_contributed_to`/`repositories_contributed_to`. It is repeatable against any stack that syncs commits from GitHub (essentially every tracked repository), and the "victim" login only needs to be a known/guessable existing Shipit user — no secrets required. This is a data-integrity/audit-attribution corruption issue rather than a direct RCE, credential-exfiltration, or unauthorized-deploy primitive: nothing in the traced code shows `Commit#author` being consulted by authorization checks (`authorized?`, `require_permission!`) or by deploy/merge decision logic (`MergeRequest#merge_requested_by` is a separate field set only via `MergeRequest.request_merge!`, driven by the authenticated actor, not by `Commit#author`). No path was found in this engine where forging `Commit#author` alone triggers an unauthorized deploy, rollback, or merge, or leaks a secret.

### Likelihood Explanation
Low operational barrier: any external contributor able to open a PR or push a commit to a tracked branch can supply an arbitrary commit message. Preconditions are that the target repository/stack ingest commits from arbitrary contributors (fork PRs, or a push-accessible branch) and that the victim login exists in Shipit's `users` table (learnable from public GitHub activity/Shipit UI). Feasible and repeatable with no rate limiting or special configuration beyond typical PR-based workflows.

### Recommendation
Do not derive `Commit#author` from free-text commit-message parsing of attacker-controlled content. If the "Merge-Requested-By" attribution is desired, source it only from `Commit#merge_request&.merge_requested_by`, which is set through the authenticated `MergeRequest.request_merge!(stack, number, user)` call (driven by a real, authorized Shipit session/API actor), not from parsing arbitrary GitHub commit messages. At minimum, restrict the message-based match to commits actually created by the merge itself (e.g., verify the commit was produced by Shipit's own merge action, such as checking it's the designated merge commit associated with a `MergeRequest` in `merged` state) rather than trusting any commit whose message happens to contain the literal string.

### Proof of Concept
In `test/models/commits_test.rb` (or `test/models/users_test.rb`), add a minitest case:
1. Build a fake `github_commit` OpenStruct/stub with:
   - `sha`: arbitrary sha
   - `author`: a stub GitHub user object representing the real attacker (e.g., `login: 'attacker'`, distinct `id`)
   - `commit.author.date`, `commit.committer.date`: valid timestamps
   - `commit.message`: `"Some innocuous title\n\nMerge-Requested-By: victim\n"`
   - `commit.committer`: attacker-controlled committer stub
2. Create a pre-existing `Shipit::User` with `login: 'victim'`.
3. Call `commit = Shipit::Commit.from_github(github_commit_stub)`.
4. Assert `commit.author.login == 'victim'` while asserting the stubbed `github_commit.author.login == 'attacker'` — demonstrating `commit.author.login != github_commit.author.login`, i.e. the equality `Commit#author == GitHub commit author` is broken.
5. No live GitHub call is needed if `User.find_or_create_by_login!` is stubbed/short-circuited (the victim user already exists, so `find_or_create_by!` finds it without hitting `Shipit.github.api.user(login)`).

### Citations

**File:** app/models/shipit/commit.rb (L105-107)
```ruby
    def self.from_github(commit)
      author = User.find_or_create_author_from_github_commit(commit)
      author ||= Anonymous.new
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

**File:** app/models/shipit/merge_request.rb (L7-7)
```ruby
    MERGE_REQUEST_FIELD = 'Merge-Requested-By'
```

**File:** app/models/shipit/merge_request.rb (L247-260)
```ruby
    def github_pull_request=(github_pull_request)
      self.github_id = github_pull_request.id
      self.api_url = github_pull_request.url
      self.title = github_pull_request.title
      self.state = github_pull_request.state
      self.mergeable = github_pull_request.mergeable
      self.additions = github_pull_request.additions
      self.deletions = github_pull_request.deletions
      self.branch = github_pull_request.head.ref
      self.head = find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha, detached: true)
      self.merged_at = github_pull_request.merged_at
      self.base_ref = github_pull_request.base.ref
      self.base_commit = find_or_create_commit_from_github_by_sha!(github_pull_request.base.sha, detached: true)
    end
```

**File:** app/models/shipit/merge_request.rb (L262-266)
```ruby
    def merge_message
      return title unless merge_requested_by

      "#{title}\n\n#{MERGE_REQUEST_FIELD}: #{merge_requested_by.login}\n"
    end
```

**File:** app/models/shipit/merge_request.rb (L303-309)
```ruby
    def find_or_create_commit_from_github_by_sha!(sha, attributes)
      if commit = stack.commits.by_sha(sha)
        commit
      else
        github_commit = stack.github_api.commit(stack.github_repo_name, sha)
        stack.commits.create_from_github!(github_commit, attributes)
      end
```

**File:** app/jobs/shipit/github_sync_job.rb (L51-53)
```ruby
    def append_commit(gh_commit)
      stack.commits.create_from_github!(gh_commit)
    end
```
