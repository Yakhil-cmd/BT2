### Title
CheckSuiteHandler triggers RefreshCheckRunsJob on a victim stack using a signature verified for a different org - ([File: app/models/shipit/webhooks/handlers/check_suite_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the webhook secret to verify against based on `params.dig('repository','owner','login')`, while `Handler#stacks` (used by `CheckSuiteHandler#process`) looks up the target repository from a different, independently-controlled field: `payload.dig('repository','full_name')`. Because both fields live in the same attacker-crafted JSON body and are read independently, an attacker who controls one org's webhook secret can forge a payload whose `repository.owner.login` matches their own org (so the signature check passes) while `repository.full_name` names a victim repository, causing the victim's stack/commit to have `RefreshCheckRunsJob` enqueued.

### Finding Description
The claimed binding is: `org verifying the webhook signature (repository.owner.login)` == `org owning the stack whose check runs are refreshed (repository.full_name)`.

Trace:
- `app/controllers/shipit/webhooks_controller.rb:24-38` (`verify_signature`) computes `repository_owner` via `repository_owner` (line 59-62): `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, and uses it to select the `GitHubApp` (and thus the `webhook_secret`) via `Shipit.github(organization: repository_owner)` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` only compares the HMAC-SHA1 of the raw body against the secret configured for *that org* [3](#0-2) .
- Once verified, the whole raw JSON body (the same attacker-controlled payload) is dispatched to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) .
- `Handler#stacks` resolves the target repository using a *different* field of the same payload: `payload.dig('repository', 'full_name')` [5](#0-4) .
- `CheckSuiteHandler#process` then does `stacks.where(branch: params.check_suite.head_branch).each { |stack| stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!) }` [6](#0-5) .

Nothing ties `repository.owner.login` (used for signature selection) to `repository.full_name` (used for stack resolution) — they are two independently attacker-supplied strings in a single JSON body that the attacker fully controls and signs themselves. An attacker who is an org admin/repo owner for `attacker-org` (and therefore knows or controls `attacker-org`'s webhook secret in a multi-org Shipit config) can send:
```
POST /webhooks
X-Github-Event: check_suite
X-Hub-Signature: sha1=<HMAC using attacker-org's known secret>
{
  "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo" },
  "check_suite": { "head_branch": "master", "head_sha": "<victim commit sha>" }
}
```
This passes `verify_signature` (secret matches `attacker-org`), passes `drop_unhandled_event` (check_suite is handled), and is then dispatched to `CheckSuiteHandler`, which resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `RefreshCheckRunsJob`-related work for the victim's tracked commit if its branch/sha match. No existing guard (`ExplicitParameters` schema, `drop_unhandled_event`, model validations) checks that the org used for signature verification matches the org named in `repository.full_name`.

### Impact Explanation
A payload signed by attacker-controlled organization credentials can affect a victim repository's stack/commit state — `schedule_refresh_check_runs!` is invoked on the victim's `Commit`, which enqueues a job that will interact with the victim repository's check runs (a deployability signal used by Shipit). This is a cross-org write triggered by a payload that never authenticated for the target org, matching the "payload for one repository mutating another's stack/commit" critical category. It is repeatable against any repository as long as the attacker can guess/target its `full_name`, branch, and a tracked commit sha (the sha is typically public/known via GitHub for open repos).

### Likelihood Explanation
Preconditions: the Shipit deployment must be configured in the multi-org mode (`secrets.github` keyed by organization, each with its own `webhook_secret`), and the attacker must control at least one such org's webhook secret (i.e., they operate/administer a repository whose org is registered with this Shipit instance — consistent with the attacker model of "any GitHub user who can... emit webhooks from a repository they own"). Given that, the attack costs only crafting one HTTP POST with a valid HMAC computed from a secret the attacker already possesses; no GitHub-side interaction, GitHub App private key, or Shipit session is required. Fully repeatable.

### Recommendation
Bind the org used for signature verification to the org actually acted upon: in `WebhooksController`/`Handler`, derive `repository_owner` and `repository_name` from the exact same field of the payload (e.g., always parse the owner login out of `repository.full_name`), or explicitly verify that `params.dig('repository','owner','login')` matches the owner segment of `payload.dig('repository','full_name')` before processing, rejecting the request otherwise.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb` or a handler unit test, no live GitHub):
1. Configure two orgs in `Shipit.github` config fixtures: `attacker-org` with `webhook_secret: "attacker-secret"`, and `victim-org` with a different secret.
2. Create a `Stack` for `victim-org/victim-repo` tracking branch `master`, and a `Commit` on that stack with `sha: "victimsha"`.
3. Build a JSON body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "check_suite": {"head_branch": "master", "head_sha": "victimsha"}}`.
4. Sign it with `attacker-org`'s known secret (`sha1=` + HMAC-SHA1 hexdigest).
5. POST to `/webhooks` with header `X-Github-Event: check_suite` and the computed `X-Hub-Signature`.
6. Assert response is `200`/`:ok` (signature accepted).
7. Assert `RefreshCheckRunsJob` (or whatever `schedule_refresh_check_runs!` enqueues) was enqueued for the `victim-org` commit `victimsha` — i.e. `assert_enqueued_with(job: RefreshCheckRunsJob, args: [commit.id])` — demonstrating the binding `verifying-org == acted-upon-org` is broken.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
