This confirms an exploitable analog. Let me finalize the analysis.

`StatusHandler#process` and `CheckSuiteHandler#process` (partially) act on data (`sha`, `branch`) that is scoped only by whatever GitHub App/organization the signature was verified against — but the commit/stack lookup that follows is **not** re-scoped to that same organization/repository.

### Title
Webhook Signature Verified for Attacker's Own Organization but Commit Status Applied to Any Stack Sharing the Same SHA - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to check the HMAC against using `repository_owner`, a value taken straight from the attacker-controlled JSON payload (`params.dig('repository','owner','login')`), and then dispatches the *entire* payload to handlers such as `StatusHandler`. `StatusHandler#process` looks up commits purely by `sha` across the whole `Commit` table, with no scoping to the repository/organization whose signature was actually verified.

### Finding Description
The binding that should hold is:
`organization that authenticated the webhook == repository/stack whose state is mutated`

In `app/controllers/shipit/webhooks_controller.rb`, `verify_signature` computes `repository_owner` from the payload and fetches the corresponding `GithubApp`/secret via `Shipit.github(organization: repository_owner)` [1](#0-0) . Because this value is read from the untrusted JSON body itself, an attacker who owns/administers their own GitHub organization "attacker-org" (with its own Shipit-configured GitHub App, per the documented multi-org support in `docs/setup.md`) can legitimately obtain a webhook whose HMAC is valid for `repository_owner = "attacker-org"`.

The signature check only proves "this payload was signed by attacker-org's webhook secret" — it says nothing about the `sha`/`branches`/`check_suite.head_sha` fields also embedded in that same JSON body. Once signature verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1)  forwards the raw, attacker-controlled `params` unmodified to handlers.

`StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

This queries `Commit` globally, with no filter by repository or organization. If a victim stack happens to contain a commit with the same SHA the attacker specifies (trivial to arrange — SHAs are content hashes, and an attacker can push the exact same tree/commit to their own public/private repo, or simply guess/observe a public commit SHA already tracked by a victim Shipit stack), the attacker can inject a forged CI status (`state: success`, arbitrary `context`) for that commit even though the signature was only ever validated against the attacker's own organization's secret.

`CheckSuiteHandler#process` has a partial mitigating scope (`stacks.where(branch: params.check_suite.head_branch)`) but still matches purely on `branch` name and `sha`, not on organization/repository identity, so a stack in a different org with the same branch name and a commit of the same SHA is equally reachable [4](#0-3) .

### Impact Explanation
This allows an unprivileged attacker who administers nothing more than their own GitHub organization (which they have onboarded into a multi-org Shipit instance, or which was already a legitimate tenant) to forge a "success" CI status for a commit belonging to a *different* organization's stack. Since Shipit's merge queue and deploy safety checks (`ci.require`) gate on commit status state, this can be used to bypass CI requirements and trigger an unauthorized merge or deploy on a stack the attacker does not control — a cross-repository/cross-organization write of trusted state, satisfying the "unauthorized deploy/merge" high-impact criterion.

### Likelihood Explanation
Requires the attacker to control at least one legitimately configured GitHub organization/App in the Shipit multi-org config (a real but not-highly-privileged bar — any onboarded org counts, they need no Shipit account, GitHub team membership, or API token) and to get a target commit SHA to collide with one tracked in a victim stack (achievable since commit SHAs are derived from content and can be intentionally reproduced by pushing identical commits, or simply reusing SHAs from public repositories that Shipit also tracks).

### Recommendation
Scope status/check-suite (and any other webhook-driven) lookups to the repository/organization that was actually verified for that request, e.g., join through `Repository`/`Stack` filtered by the verified `repository_owner`/`repository.name`, mirroring the fix suggested in the analogous report ("use the identity established at verification time as an equality constraint on the resource being mutated"), rather than trusting repository/organization fields embedded in the same unauthenticated JSON body for downstream lookups.

### Proof of Concept
1. Attacker administers `attacker-org`, a legitimate multi-org GitHub App entry in Shipit's `secrets.yml` (`github.attacker-org.webhook_secret` known to the attacker).
2. Attacker identifies (or reproduces) a commit SHA `X` that is also tracked by `victim-org/victim-repo`'s Shipit stack (e.g., a shared open-source dependency commit, or by crafting an identical tree/commit and pushing it to their own throwaway repo so Shipit records the same SHA under `attacker-org`).
3. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, a body `{"sha": "X", "state": "success", "context": "ci/required-check", "repository": {"owner": {"login": "attacker-org"}, "name": "whatever"}}`, and `X-Hub-Signature` computed with `attacker-org`'s own webhook secret.
4. `verify_signature` passes because the HMAC is valid for `attacker-org`.
5. `StatusHandler#process` matches `Commit.where(sha: "X")`, which includes the victim's commit, and calls `create_status_from_github!`, marking the victim's commit as passing CI — potentially unblocking an unauthorized merge/deploy on `victim-org/victim-repo`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
