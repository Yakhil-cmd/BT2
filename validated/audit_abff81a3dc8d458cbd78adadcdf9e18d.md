### Title
Login-string collision in `User.find_or_create_by_login!` lets a stale/reused GitHub username resolve to a pre-existing `User` row - ([File: app/models/shipit/user.rb])

### Summary
`User.find_or_create_by_login!` binds identity purely on the mutable `login` string, and the "find" branch of `find_or_create_by!` returns any pre-existing row matching that login without ever checking `github_id`. Because GitHub usernames are mutable and can be renamed/freed and later re-registered by a different account, a `User` row created originally for one real GitHub account can later be silently reused for a completely different GitHub account that claims the freed login, without any re-verification against `github_id`.

### Finding Description
The claimed binding is: `User#id` resolved by `find_or_create_by_login!(login)` == `User#id` resolved by `find_or_create_from_github(github_user)` for the same real-world GitHub account, and never for two different accounts sharing a login string.

`find_or_create_by_login!` is implemented as: [1](#0-0) 

`find_or_create_by!(login:)` first runs `find_by(login:)`; if a row already exists it is returned immediately and the block (which calls `Shipit.github.api.user(login)` to authoritatively verify who currently owns that login) is **never executed**. Verification against the real GitHub owner only happens on the creation path, not on the "already exists" path.

This is reachable from `PullRequest#github_pull_request=`, driven by webhook-delivered, GitHub-verified `pull_request.user.login`: [2](#0-1) 

and also from `ReviewStackAdapter#user`, keyed on `params.sender["login"]`: [3](#0-2) 

and, most severely, from `User.find_or_create_author_from_github_commit`, which extracts the login from a **fully attacker-controlled commit message trailer** (`Merge-Requested-By: <anything matching [\w\-.]+>`) with no GitHub verification at all on the match path: [4](#0-3) 

Root cause: identity is keyed by the mutable `login` string on the "found" branch, instead of the immutable `github_id` that `find_or_create_from_github`/`find_from_github` correctly use: [5](#0-4) 

Exploit flow (commit-message vector, the most directly attacker-controlled): an attacker pushes a commit to a branch/PR they control with a message body containing a line `Merge-Requested-By: <existing-shipit-login>` (e.g., the login of a real teammate/maintainer already known to have a `User` row in Shipit, discoverable from public commit history/PRs). When Shipit processes that commit (`find_or_create_author_from_github_commit`), it matches the trailer, calls `find_or_create_by_login!('<existing-shipit-login>')`, finds the pre-existing row, and attributes the commit's authorship to that real user's `User` record - with no call out to GitHub to confirm the attacker actually is that account.

None of the listed guards prevent this: webhook signature verification (`verify_signature`) only proves the payload came from GitHub for the repository in question, it does not constrain the content of a commit message the attacker writes themselves; `ExplicitParameters` schemas validate shape, not cross-referencing `github_id`; `User#authorized?` is unrelated (it gates team-based authorization, not identity binding); there is no validation anywhere in `User` that re-checks `github_id` against `login` before reuse.

### Impact Explanation
The attacker can cause a `Commit`'s `author`/`committer` (via `find_or_create_author_from_github_commit`/`find_or_create_committer_from_github_commit`) or a `PullRequest`'s `user`/`assignees` to be silently attributed to a pre-existing, real `User` row that they do not control, chosen by simply naming a string in their own commit message or (with the login-squatting variant) by registering a freed GitHub username. This is identity confusion / misattribution of commit authorship and PR association to an account that may be a real Shipit-authenticated user (same row addressable by `session[:user_id]` after that real user's next OAuth login, since `find_or_create_from_github` looks up by immutable `github_id` and will find the same row and just refresh its `login`/`name`/etc.). This is repeatable against any repository the attacker can push a branch/PR to, for any target login the attacker chooses to reference in a commit trailer.

### Likelihood Explanation
The commit-message (`Merge-Requested-By:`) vector requires no external precondition and no privileged access: any unprivileged GitHub user who can open a PR/push a commit against a Shipit-tracked repository can embed an arbitrary trailer referencing any existing Shipit login they can enumerate (e.g., from the Shipit UI/API showing commit authors, or GitHub org members). This is low-cost and fully repeatable. The webhook `pull_request.user.login` / `sender.login` vector additionally requires the target login to be reused/squatted (an external GitHub-side event), which is a real but lower-frequency precondition.

### Recommendation
Do not resolve/attach identity purely by matching the mutable `login` string against pre-existing rows without re-verifying against `github_id`. In `find_or_create_by_login!`, always resolve the login to a `github_id` via `Shipit.github.api.user(login)` first (or accept a `github_id` alongside `login`), then `find_or_create_by(github_id:)`, updating `login` if it changed - mirroring the pattern already used correctly in `find_or_create_from_github`/`find_from_github`. At minimum, for the `Merge-Requested-By` commit-trailer path, treat it as unverified/attacker-controlled text and either drop it or explicitly re-verify the resolved user's `github_id` against a GitHub API lookup before use, rather than trusting an existing `login`-matched row.

### Proof of Concept
Minitest plan (`test/models/users_test.rb`, no live GitHub - stub `Shipit.github.api`):
1. Create user A: `alice = User.find_or_create_by_login!('shared_login')`, stubbing `Shipit.github.api.user('shared_login')` to return `stub(id: 100, login: 'shared_login', ...)`. Assert `alice.github_id == 100`.
2. Simulate the real account renaming away and a different account taking the freed login, or simply simulate the attacker-controlled commit-message path: call `User.find_or_create_author_from_github_commit(github_commit)` where `github_commit.commit.message` is `"...\n\nMerge-Requested-By: shared_login\n"` and `github_commit.author`/`github_commit.commit.author` is an **unrelated** stub with `id: 999, login: 'attacker'`.
3. Assert the returned user's `id == alice.id` and `github_id == 100`, i.e. `Commit#author` ends up bound to `alice` (github_id 100) even though the actual commit author on GitHub is `github_id: 999`.
4. Assert this violates the intended binding: `User.find_or_create_by_login!('shared_login').github_id != 999` while the real committer's `github_id` is `999` - demonstrating the collapse of two distinct real-world identities into one `User` row, addressable later via `alice`'s `session[:user_id]` if `alice` logs in through OAuth (`find_or_create_from_github(stub(id: 100, login: 'shared_login'))` returns the same row).

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

**File:** app/models/shipit/user.rb (L46-54)
```ruby
    def self.find_or_create_from_github(github_user)
      find_from_github(github_user) || create_from_github(github_user)
    end

    def self.find_from_github(github_user)
      return unless github_user.id

      find_by(github_id: github_user.id)
    end
```

**File:** app/models/shipit/pull_request.rb (L36-50)
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
      self.labels = github_pull_request.labels.map(&:name)
      self.head = find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L52-54)
```ruby
          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end
```
