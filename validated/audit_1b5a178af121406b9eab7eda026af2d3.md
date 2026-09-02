### Title
Commit author attribution is spoofable via forged `Merge-Requested-By:` trailer in pushed commit messages - (`File: app/models/shipit/user.rb`)

### Summary
`Shipit::User.find_or_create_author_from_github_commit` blindly trusts a `Merge-Requested-By: <login>` line embedded in a commit's message and attributes authorship of that commit to whatever existing `User` row matches `<login>`, with no check that the actual pusher/committer is related to that login. Since commit messages are attacker-controlled content in a repository the attacker owns, and the webhook signature only proves the payload came from a GitHub org/repo that owns a valid `webhook_secret` (not that the *content* of a commit message is trustworthy), an attacker can push a commit to their own repo with a forged trailer naming a real, privileged Shipit user and have it recorded as authored by that victim.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`Commit#author` (the identity Shipit stores/uses for blame, deploy eligibility and merge audit trail) should equal the GitHub identity that actually authored/pushed the commit (`github_commit.author`/`github_commit.commit.author`), but instead it can equal an arbitrary existing `Shipit::User` chosen by attacker-controlled text in the commit message.

Code path:
- `Shipit::User.find_or_create_author_from_github_commit` [1](#0-0)  matches the commit message against `/^#{MergeRequest::MERGE_REQUEST_FIELD}: ([\w\-.]+)$/` (`MERGE_REQUEST_FIELD = 'Merge-Requested-By'` [2](#0-1) ) and, on a match, calls `find_or_create_by_login!(match_info[1])` [3](#0-2) , returning that user as the commit's author **without any relation to who actually pushed/committed**.
- `Shipit::Commit.from_github` calls this method directly to set `author:` on the new `Commit` record: [4](#0-3) .

Root cause: the trailer parsing was designed for Shipit's own internally-generated merge commits (`MergeRequest#merge_message` writes `"#{title}\n\n#{MERGE_REQUEST_FIELD}: #{merge_requested_by.login}\n"` when Shipit itself performs the GitHub merge, see [5](#0-4) ), but `find_or_create_author_from_github_commit` has no way to distinguish a commit message written by Shipit's own merge action from one crafted by any GitHub user with push/commit access to any repository whose commits eventually get ingested (via push webhook → `Commit.from_github`, or via `identify_merge_request`/`MergeRequest#find_or_create_commit_from_github_by_sha!` → `stack.commits.create_from_github!` at [6](#0-5) ). The regex/lookup trusts the literal string bytes of the commit message as an authorization signal.

I was not able to fully trace the exact `WebhooksController`/`Handlers::PushHandler` invocation chain within this session (partial reads only confirmed `push_handler.rb` exists and that webhook signature verification lives in `lib/shipit/github_app.rb` and `app/controllers/shipit/webhooks_controller.rb`), so I cannot state with certainty in this answer whether push-webhook-triggered commit ingestion for a stack's *configured* repository actually reaches `Commit.from_github` for every pushed commit (as opposed to only for commits on the tracked branch of a stack that already exists and is configured with that repository). The signature check binds "this payload really came from GitHub for repository X," not "this specific commit message field is trustworthy" — so even a fully legitimate, properly-signed webhook for a repository an attacker controls (or a PR branch on a repo with a merge queue) can carry this forged trailer.

Existing guards do not close this gap: `verify_signature`/`GitHubApp#verify_webhook_signature` verify the webhook came from GitHub for a specific repo/org, not that a commit-message trailer inside the payload is truthful; `force_github_authentication`, `User#authorized?`, and `require_permission!` govern who can act as a logged-in Shipit user via OAuth, not how commits ingested from GitHub get attributed; there is no validation in `find_or_create_author_from_github_commit` that the resolved login is the actual committer/author of the commit, nor that the pusher is a maintainer of the target stack's repository.

### Impact Explanation
A successful forgery causes a `Shipit::Commit` row to be falsely attributed (`author_id`) to a privileged/target `Shipit::User`, affecting: blame/attribution display, `User#repositories_contributed_to` / `stacks_contributed_to` computed from `Commit.where('author_id = :id ...')`, and any deploy-eligibility or merge-audit logic that keys off commit authorship. This is a cross-tenant/cross-identity record write: a commit that a repository legitimately pushed gets an authorship claim about a person who never touched it. It does not directly grant the attacker deploy/merge privileges themselves (the attacker doesn't gain `User#authorized?` or session access), and it does not leak secrets or achieve RCE. Given the severity bar defined in this audit (Critical requires RCE, auth bypass, secret exfiltration, cross-stack mutation, or unauthorized deploy/rollback/merge; High requires escalation into `Shipit.github_teams`, unauthenticated read of stack/task state, SSRF with credentials, or session fixation), this finding is a data-integrity/attribution-forgery issue on a `Commit` record — it does not, on the evidence gathered, clear either bar: it does not by itself flip `authorized?`, does not bypass authentication, and does not cause a deploy/merge to execute that wouldn't otherwise happen, since `MergeRequest#merge!`'s actual merge action is invoked by Shipit's own scheduler against the GitHub API, not driven by the forged author field.

### Likelihood Explanation
Low cost for the attacker (any commit message trailer in a repo/branch they control), but the actual reachability into a tracked stack's commit history (versus an unrelated repo an attacker fully owns) requires the target repository to already be configured as a Shipit stack, and requires the forged commit to actually land in that stack's tracked branch/PR path — this can't be done against "arbitrary repositories or stacks" the attacker doesn't have push/PR access to. I was unable to confirm within the available context whether `Handlers::PushHandler` ingests commits from arbitrary pushed branches/refs or only from the stack's configured branch, which materially affects how easily this is triggered end-to-end.

### Recommendation
In `Shipit::User.find_or_create_author_from_github_commit`, only trust the `Merge-Requested-By` trailer when the commit is verified to be the actual merge commit created by Shipit's own `MergeRequest#merge!` for a `MergeRequest` record already tracked with a matching `merge_requested_by`, rather than pattern-matching arbitrary commit message text from any ingested commit. Concretely, resolve authorship for merge commits via `MergeRequest#merge_requested_by` from the existing `merge_request` association (as already done in `Commit#identify_merge_request`, [7](#0-6) ) instead of re-parsing the raw commit message inside `User`, and remove/harden the regex-based trust path in `find_or_create_author_from_github_commit`.

### Proof of Concept
Minitest plan (`test/models/users_test.rb`, informational — not to be run without further verifying reachability from the webhook path):
```ruby
test "find_or_create_author_from_github_commit trusts forged Merge-Requested-By trailer" do
  victim = shipit_users(:walrus) # or any existing privileged fixture user
  forged_commit = stub_github_commit(
    sha: "deadbeef",
    message: "Some attacker commit\n\nMerge-Requested-By: #{victim.login}\n",
    author: stub_github_author(login: "attacker"),
    committer: stub_github_author(login: "attacker")
  )

  resolved_author = Shipit::User.find_or_create_author_from_github_commit(forged_commit)

  assert_equal victim, resolved_author
  # Equality that SHOULD hold but doesn't: resolved_author == actual pusher (attacker),
  # not an arbitrary existing user named in the message.
end
```
This demonstrates the divergence between the claimed authorship and the actual GitHub identity that pushed the commit, but confirming full end-to-end exploitability through `WebhooksController#create` → `Handlers::PushHandler` requires further tracing of that handler, which was not completed in this session.

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

**File:** app/models/shipit/merge_request.rb (L7-7)
```ruby
    MERGE_REQUEST_FIELD = 'Merge-Requested-By'
```

**File:** app/models/shipit/merge_request.rb (L262-266)
```ruby
    def merge_message
      return title unless merge_requested_by

      "#{title}\n\n#{MERGE_REQUEST_FIELD}: #{merge_requested_by.login}\n"
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
