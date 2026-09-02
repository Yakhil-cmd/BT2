### Title
Forged commit authorship via attacker-controlled `Merge-Requested-By` field in `find_or_create_author_from_github_commit` - ([File: app/models/shipit/user.rb])

### Summary
`Shipit::User.find_or_create_author_from_github_commit` trusts a free-text `Merge-Requested-By: <login>` line embedded in a GitHub commit's own message to determine the `author` of that commit, rather than relying on the commit's actual `author`/`committer` GitHub identity. An attacker who authors a commit in their own fork (which becomes a pull request's `head` commit) fully controls that commit message and can therefore forge attribution of that commit to any existing Shipit `User` login.

### Finding Description
The broken binding: `User.find_or_create_author_from_github_commit(github_commit)` should equal the GitHub identity of `github_commit.author`/`github_commit.commit.author` (the actual committer), but instead equals `find_or_create_by_login!(match_info[1])` whenever the attacker-controlled `github_commit.commit.message` matches `/^Merge-Requested-By: ([\w\-.]+)$/`: [1](#0-0) 

This method is invoked from `Commit.from_github`, which is called for the head/base commits of a pull request when Shipit fetches PR data: [2](#0-1) [3](#0-2) 

`MergeRequest#github_pull_request=` (invoked during `refresh!`, which is triggered by webhook-driven pull-request syncing) resolves `self.head` via `find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha, ...)`, which fetches the commit from GitHub and calls `stack.commits.create_from_github!` → `Commit.from_github` → `User.find_or_create_author_from_github_commit`: [4](#0-3) 

The attacker's own fork commit is entirely attacker-controlled content, including its commit message. By crafting a commit message containing a trailing line `Merge-Requested-By: walrus` (an arbitrary, existing, privileged login), the attacker causes the created `Commit#author` for their PR's head commit to resolve to `Shipit::User` with `login == "walrus"` via `find_or_create_by_login!`, rather than to a user matching the attacker's real GitHub identity (`github_commit.author`). `identify_merge_request` (the `before_create` callback that can override `author` with `merge_request.merge_requested_by`) only fires when the commit message itself matches an already-known merge-commit/PR-number pattern (`message_parser.pull_request?`), which is unrelated to and does not gate this regex-driven override on the head commit — so it does not prevent the forgery for typical feature-branch commits: [5](#0-4) 

No signature verification, permission check, or model validation constrains the free-text commit message content; `Merge-Requested-By` is intended to be written only by Shipit itself when it performs an actual merge (`MergeRequest#merge_message`), but `find_or_create_author_from_github_commit` naively trusts the same string pattern regardless of who authored the underlying commit: [6](#0-5) 

### Impact Explanation
The result is misattributed authorship recorded in Shipit's `Commit` table for a PR's head commit — an arbitrary named existing user (e.g., an org admin, a maintainer, or a bot account) is recorded as the "author" of a commit they never wrote. This corrupts provenance data used for UI display, `stacks_contributed_to`/`repositories_contributed_to` aggregation, and general commit bookkeeping. However, I could not confirm, within the code reviewed, that this forged `author` field is used anywhere as an authorization gate for triggering an actual merge, deploy, or rollback (`MergeRequest.request_merge!` takes an explicit `user` argument from the authenticated request context, not from `Commit#author`), nor that it grants the attacker any privilege escalation into `Shipit.github_teams`. Within the given severity taxonomy, this is best characterized as a data-integrity/spoofing issue affecting commit provenance display rather than a demonstrated authentication bypass, unauthorized merge, or credential exfiltration — I was not able to trace a path from this forged `author` field to any privileged action or secret disclosure in the code available to me.

### Likelihood Explanation
Preconditions are minimal: an attacker only needs push access to their own fork and the ability to open a pull request against the target stack's repository, both of which are explicitly in-scope attacker capabilities under the rules. No secrets, session, or team membership are required. Exploitation is trivially repeatable per PR/commit.

### Recommendation
`find_or_create_author_from_github_commit` should not trust a `Merge-Requested-By` string embedded in an arbitrary commit's own message as a substitute for the commit's actual GitHub author. If this field is only meant to reflect Shipit-generated merge commits, the lookup should be scoped to commits that Shipit itself created during a `merge!` call (e.g., by matching against the known `MergeRequest#merge_requested_by` for that specific merge, verified via the actual merge commit SHA Shipit produced), rather than regex-matching the freely attacker-controlled `commit.message` of any commit fetched from GitHub.

### Proof of Concept
minitest plan (`test/models/users_test.rb`):
1. Build a stub `github_commit` where `commit.message` is `"Fix bug\n\nMerge-Requested-By: walrus\n"`, and `author`/`commit.author` are set to the attacker's own GitHub identity (distinct `id`/`login` from `shipit_users(:walrus)`).
2. Call `Shipit::User.find_or_create_author_from_github_commit(github_commit)`.
3. Assert equality on both sides of the binding:
   - Expected (per intended binding): returned user's `github_id` == attacker's `github_commit.author.id` (i.e., `refute_equal shipit_users(:walrus), result`).
   - Actual (observed bug): `assert_equal shipit_users(:walrus), result` — the arbitrary named login wins over the true commit author, demonstrating the forged attribution.

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

**File:** app/models/shipit/merge_request.rb (L303-312)
```ruby
    def find_or_create_commit_from_github_by_sha!(sha, attributes)
      if commit = stack.commits.by_sha(sha)
        commit
      else
        github_commit = stack.github_api.commit(stack.github_repo_name, sha)
        stack.commits.create_from_github!(github_commit, attributes)
      end
    rescue ActiveRecord::RecordNotUnique
      retry
    end
```
