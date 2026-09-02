All confirmed usages of `Commit.by_sha`/`by_sha!` in controllers (`app/controllers/shipit/api/deploys_controller.rb:20`, `app/controllers/shipit/api/rollbacks_controller.rb:15`, `app/controllers/shipit/deploys_controller.rb:13`) call it as `stack.commits.by_sha(...)`, i.e. on the `has_many :commits` association scope, which implicitly chains `where(stack_id: stack.id)` before the `where('sha like ?', ...)` clause. So the cross-stack short-SHA-collision scenario for target 1 does not hold: the equality `stack.id == commit.stack_id` is enforced by the association scope on every reachable controller path, and no controller calls `Commit.by_sha!` unscoped. [1](#0-0) [2](#0-1) [3](#0-2) 

For target 2, `Webhooks::Handlers::StatusHandler#process` resolves commits with `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, which is a global, exact-match query across **all** stacks with no `repository.full_name` / `stack.github_repo_name` check at all. [4](#0-3)  The webhook signature check in `WebhooksController#verify_signature` only verifies that the payload was signed by the GitHub org named in `params.dig('repository','owner','login')` — it never checks that the `repository.full_name` in the payload matches the `github_repo_name` of the stack(s) owning the matched commit(s). [5](#0-4)  `Commit#create_status_from_github!` then writes attacker-supplied `target_url`/`description`/`state` verbatim via `statuses.replicate_from_github!(stack_id, github_status)`. [6](#0-5) [7](#0-6) 

The broken binding is: `payload.repository.full_name == stack.github_repo_name` (for every `stack_id` reachable through the matched commit row), which is never checked before `create_status_from_github!` is invoked. This is exploitable, but only under a real SHA collision — since the match is `where(sha: params.sha)` (exact 40-char equality, not a `LIKE` prefix), the attacker cannot brute-force a collision; they need a commit whose SHA is byte-identical to a commit that already exists in a victim stack's `commits` table. Git SHA-1 identifies content+history deterministically, so the realistic way to obtain such a match is: the attacker's repo is a fork of (or shares commit history with) the victim's repo, so a commit that exists upstream in the victim's tracked stack also exists, with the identical SHA, in the attacker's own fork. The attacker then pushes/re-triggers a `status` event on their own fork with that shared SHA (which GitHub will legitimately fire on push/CI for their fork), and it gets signed by their own org/repo's webhook secret (or the org-level secret if same org) — passing `verify_signature`, since that only checks the *organization* owning the payload's `repository`, not that the repository is the one owning the target commit/stack.

This matches the "payload for one repository mutating another's stack" Critical impact category, but the precondition (shared git history / fork relationship, and both repos configured under GitHub orgs Shipit trusts) is a real, non-brute-forceable constraint — not an arbitrary attacker-chosen collision as loosely implied by the prompt. Given the exact-equality query (not `LIKE`), this is a genuine, reachable gap: **no code path checks `payload.repository.full_name` against `stack.github_repo_name` before writing a `Status` row**, confirmed at `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`.

### Title
Cross-repository Status injection via unscoped SHA lookup in StatusHandler - (app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with a global `Commit.where(sha: params.sha)` query with no verification that the webhook's `repository.full_name` matches the `github_repo_name` of the stack owning the matched commit. Because GitHub SHA-1 hashes are deterministic over content+history, a fork of a victim's repository will legitimately contain commits with identical SHAs to commits already synced into the victim's stack, letting the fork owner's own (validly-signed) `status` webhook write an attacker-controlled `target_url`/`description`/`state` onto the victim stack's commit.

### Finding Description
The broken binding is `payload.repository.full_name == stack.github_repo_name` for the stack(s) owning the commit matched by `sha`. `WebhooksController#verify_signature` verifies the payload was signed by `Shipit.github(organization: repository_owner)` where `repository_owner` is read from the payload itself [5](#0-4) , but this only proves the payload came from a repo under that GitHub org — it does not tie the payload to a specific repository or stack. `StatusHandler#process` then does:
```
Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
``` [4](#0-3) 
with no filter on `commit.stack.github_repo_name`. `create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)` [6](#0-5) , which persists `state`/`description`/`target_url`/`context` verbatim [7](#0-6) .

Exploit flow: attacker forks/owns a repo A under the same GitHub org as victim stack B; a commit already present in stack B's history is also present, with the same SHA, in repo A (common for forks or shared-history repos). Attacker triggers (or has GitHub naturally fire) a `status` event for repo A on that shared SHA with an arbitrary `target_url`/`description`. The signature check passes because it only validates org-level HMAC, not repo identity. `StatusHandler` finds all `Commit` rows with that SHA — including the one belonging to stack B — and writes the attacker's status onto stack B.

Note: this is not a brute-forceable prefix collision (the query is exact SHA equality, not `LIKE`), so it requires genuine shared git history between the attacker's and victim's repositories, not an arbitrary short-SHA guess. The separate `Commit.by_sha`/`by_sha!` short-SHA prefix-matching concern raised in the question does **not** hold: all reachable controller call sites invoke it via `stack.commits.by_sha(...)`, which is scoped by the `has_many :commits` association to `stack_id`, e.g. `app/controllers/shipit/api/deploys_controller.rb:20`, `app/controllers/shipit/api/rollbacks_controller.rb:15`, `app/controllers/shipit/deploys_controller.rb:13`.

### Impact Explanation
A same-org attacker can inject an arbitrary `target_url`/`description`/`state` `Status` record onto an unrelated stack's commit, without needing any Shipit credentials — only a fork sharing commit history with the target. This is rendered in the victim stack's deploy/task UI (stored data injection, potential for URL-based phishing/exfiltration framing) and can influence `Commit#deployable?`/CI-gated logic if the injected `state` is `success`/`failure`, since `deployable?` and `blocked?` consult `status`/`state` derived from these rows. This matches the "payload for one repository mutating another's stack, commit, task" Critical category, but is bounded to organizations where the attacker's repo shares real git history with the victim's tracked repo (typically via forking).

### Likelihood Explanation
Requires: (1) attacker and victim repos under the same GitHub organization (so the org-level webhook secret validates), (2) attacker's repo shares actual commit SHAs with the victim's tracked history (fork or common-ancestor scenario), (3) Shipit tracks both repos as stacks. This is a realistic but not universal setup (fork-based development within one GitHub org is common). No Shipit secrets, sessions, or API tokens are needed — only the ability to trigger/have GitHub emit a `status` event for the attacker's own fork.

### Recommendation
In `StatusHandler#process`, filter matched commits by verifying `commit.stack.github_repo_name == params.repository.full_name` (require `repository` in the handler's params schema) before calling `create_status_from_github!`, discarding matches for stacks whose tracked repository does not match the payload's repository.

### Proof of Concept
Minitest (`test/models/webhooks/handlers/status_handler_test.rb` or `test/controllers/webhooks_controller_test.rb`):
1. Create two stacks, `stack_a` (`github_repo_name: "attacker/repoA"`) and `stack_b` (`github_repo_name: "victim/repoB"`), both under the same `Shipit.github(organization: 'shared-org')`.
2. Create a `Commit` with `sha: "deadbeef..."` attached to `stack_b` only (simulating shared git history: assert this SHA is NOT associated with `stack_a`).
3. Post a `status` webhook payload with `repository.full_name = "attacker/repoA"`, `sha: "deadbeef..."`, `target_url: "http://evil.example/exfil"`, stubbing `verify_signature` to return true (as existing tests do).
4. Assert BEFORE: `Status.where(stack_id: stack_b.id, target_url: "http://evil.example/exfil").count == 0`.
5. Assert AFTER: currently this count becomes `1` (vulnerable) — the fix should keep it `0` unless `stack_b.github_repo_name == "attacker/repoA"`, which it does not, so the correct assertion under a fixed implementation is `assert_equal 0, Status.where(stack_id: stack_b.id, target_url: "http://evil.example/exfil").count`.

### Citations

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-21)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
```

**File:** app/controllers/shipit/deploys_controller.rb (L12-14)
```ruby
    def new
      @commit = @stack.commits.by_sha!(params[:sha])
      @commit.checks.schedule if @stack.checks?
```

**File:** app/models/shipit/commit.rb (L92-99)
```ruby
    def self.by_sha(sha)
      raise AmbiguousRevision, "Short SHA1 #{sha} is ambiguous (too short)" if sha.to_s.size < 6

      commits = where('sha like ?', "#{sha}%").take(2)
      raise AmbiguousRevision, "Short SHA1 #{sha} is ambiguous (matches multiple commits)" if commits.size > 1

      commits.first
    end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
