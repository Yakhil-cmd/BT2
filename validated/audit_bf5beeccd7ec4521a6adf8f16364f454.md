### Title
Commit message-based `pull_request_number` spoofing causes author misattribution — ([File: app/models/shipit/commit.rb])

### Summary
`Commit#identify_merge_request` trusts a regex-parsed `pull_request_number` from the raw git commit message text to look up a `MergeRequest` and reassign `Commit#author` to that MergeRequest's `merge_requested_by`, with no cross-check that the number genuinely corresponds to the commit being merged. [1](#0-0)  Because `GithubSyncJob` ingests commits straight from the GitHub git history (`stack.github_commits` / `Commit.from_github`) rather than from an authenticated webhook payload field, this can only be exploited if an attacker-authored commit message survives verbatim into the tracked branch's git history (e.g. via "rebase and merge" or "squash and merge" of the attacker's own PR, where GitHub preserves original commit text authored by the attacker).

### Finding Description
Binding claimed to be broken: `message_parser.pull_request_number` (parsed from the attacker's own git commit message) `==` the `number` of the `MergeRequest` that authentically corresponds to *that* commit's real PR.

The parser is `CommitMessage`, whose pattern is:
```ruby
GITHUB_MERGE_COMMIT_PATTERN = /\AMerge pull request #(?<pr_id>\d+) from \S+\n\n(?<pr_title>.*)/
``` [2](#0-1) 

`identify_merge_request` (a `before_create` callback on `Commit`) does:
```ruby
if merge_request = stack.merge_requests.find_by(number: message_parser.pull_request_number)
  self.merge_request = merge_request
  ...
  self.author = merge_request.merge_requested_by if merge_request.merge_requested_by
end
``` [1](#0-0) 

Commits are only created via `stack.commits.create_from_github!(gh_commit)` from `GithubSyncJob#append_commit`, which is fed by `fetch_missing_commits` walking `stack.github_commits` (the real GitHub git commit history via API), not directly from an unauthenticated webhook body. [3](#0-2)  `Commit.from_github` already sets the correct `author`/`committer` from the actual GitHub commit metadata before the `identify_merge_request` callback runs and can silently override it. [4](#0-3) 

The critical gap: the regex only checks the textual shape of the message, not whether `pr_id` is the PR that this specific commit actually belongs to. When a repository merges PRs using "rebase and merge" or "squash and merge" (not the "create a merge commit" strategy), GitHub preserves the exact commit message the PR author wrote on their own branch. Since PR authors fully control their own commit messages, an attacker can craft a commit on their own branch with a message exactly matching the pattern, e.g.:
```
Merge pull request #42 from someorg/somebranch

Some spoofed title
```
where `#42` is the number of a genuine, pre-existing `MergeRequest` belonging to another author (created e.g. via the merge-queue label flow or `MergeRequest.request_merge!`, which sets `merge_requested_by`). [5](#0-4)  If a maintainer merges the attacker's PR via rebase/squash without rewriting the message, this attacker-authored commit lands on the tracked branch and Shipit's sync ingests it verbatim. `identify_merge_request` then finds `MergeRequest #42` and reassigns `Commit#author` to `merge_request.merge_requested_by`, overwriting the correct GitHub-derived author with the identity that requested merge #42 — an unrelated (victim) user.

Existing guards do not prevent this: `verify_signature` and webhook auth only gate the *trigger* for `GithubSyncJob`, not the content of the commit data (which is fetched from the GitHub API, i.e., real git history) [6](#0-5) ; there is no validation in `identify_merge_request` or `CommitMessage` that ties the parsed `pr_id` to the actual originating pull request of the commit (e.g., via the GitHub API's own "associated pull requests" data or the merge SHA that produced the record).

### Impact Explanation
The `Commit#author` field is corrupted to point to an arbitrary existing `MergeRequest.merge_requested_by` on the same stack, misattributing authorship/responsibility for a deployed commit. This is an audit-trail integrity issue (High per the rubric's "unauthenticated read/state corruption" family is not exact, but this is a write of a false authorship record). It does **not** escalate to Critical in this codebase: `deployable?` keys off CI status/lock state, not `author` [7](#0-6) , and no authorization/merge/deploy-gating logic found keys off `Commit#author` identity. Blast radius is limited to a single stack's commit history/audit records (misattribution), not cross-tenant, RCE, or credential exposure.

### Likelihood Explanation
Exploitation requires: (1) an existing `MergeRequest` record on the target stack with a known `number` and a `merge_requested_by` set (easily observable — merge-queue PR numbers/authors are public on GitHub); (2) the repository's merge strategy allowing "rebase and merge" or "squash and merge" (not exclusively "create a merge commit"), so that the attacker's exact commit message text survives into the tracked branch; (3) a maintainer actually merging the attacker's PR without editing the auto-populated commit message. This is plausible but depends on repository configuration and human merge behavior that Shipit's engine code does not control — it is not a fully self-service, code-only bypass like the other flagged CommitMessage-related issues, since the attacker cannot force *how* the maintainer merges. It is repeatable for each qualifying merge, but the attacker doesn't fully control the trigger (a legitimate merge action is required first).

### Recommendation
Do not use client/attacker-controllable commit message text alone as the trust anchor for reassigning `Commit#author`. Options:
1. Only associate/override author when the commit is the actual `head` of a `MergeRequest` known via authenticated GitHub API data (`MergeRequest#head`/`base_commit`, populated from `github_pull_request=`) rather than free-text regex matching in `identify_merge_request`.
2. If message-based linking must be kept for backfill purposes, restrict the author override to cases where the commit was also independently verified as merged via `MergeRequest#merge!` (i.e., cross-check `merge_request.head&.sha` or the GitHub "merged_by"/PR association API instead of trusting the `pr_id` extracted from arbitrary commit text).

### Proof of Concept
Minitest plan (model-level, no live GitHub):
```ruby
test "identify_merge_request does not misattribute author from spoofed commit message" do
  stack = shipit_stacks(:shipit)
  victim = shipit_users(:walrus) # some existing user
  attacker_login = "mallory"

  merge_request = stack.merge_requests.create!(number: 42, merge_requested_by: victim)

  spoofed_message = <<~MSG
    Merge pull request #42 from attacker-org/attacker-branch

    Spoofed title unrelated to PR #42's real content
  MSG

  commit = stack.commits.create!(
    sha: "a" * 40,
    message: spoofed_message,
    author: shipit_users(:"#{attacker_login}") || User.create!(login: attacker_login),
    committer: shipit_users(:"#{attacker_login}") || User.create!(login: attacker_login),
    authored_at: Time.now,
    committed_at: Time.now
  )

  # Binding under test: attacker-embedded pull_request_number (42) == merge_request.number (42),
  # but the commit did not originate from that MergeRequest's real PR.
  refute_equal victim, commit.author, "author should remain the real committer, not merge_requested_by of an unrelated MergeRequest"
end
```
This asserts that `commit.author` ends up as `victim` (proving the vulnerability) versus remaining the true GitHub-derived author (proving a fix). Note: exercising the full ingestion path (`Commit.from_github` + `GithubSyncJob`) would require mocking `stack.github_commits`/Octokit responses, since GitHub API access is out of scope for this proof.

### Citations

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L316-324)
```ruby
    def identify_merge_request
      return unless message_parser.pull_request?

      if merge_request = stack.merge_requests.find_by(number: message_parser.pull_request_number)
        self.merge_request = merge_request
        self.pull_request_number = merge_request.number
        self.pull_request_title = merge_request.title
        self.author = merge_request.merge_requested_by if merge_request.merge_requested_by
      end
```

**File:** app/models/shipit/commit_message.rb (L5-17)
```ruby
    GITHUB_MERGE_COMMIT_PATTERN = /\AMerge pull request #(?<pr_id>\d+) from \S+\n\n(?<pr_title>.*)/

    def initialize(text)
      @text = text
    end

    def pull_request?
      !!parsed
    end

    def pull_request_number
      parsed && parsed['pr_id'].to_i
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-53)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end

    def append_commit(gh_commit)
      stack.commits.create_from_github!(gh_commit)
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L55-69)
```ruby
    def fetch_missing_commits(&block)
      commits = []
      github_api = stack&.github_api
      iterator = Shipit::FirstParentCommitsIterator.new(github_api:, &block)
      iterator.each_with_index do |commit, index|
        break if index >= MAX_FETCHED_COMMITS

        if shared_parent = lookup_commit(commit.sha)
          return commits, shared_parent
        end

        commits.unshift(commit)
      end
      [commits, nil]
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
