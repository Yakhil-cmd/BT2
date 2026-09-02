### Title
Cross-repository commit status forgery via unscoped `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against a single GitHub *organization* (derived from `repository.owner.login` / `organization.login` in the payload), then dispatches the parsed payload to the matching event handler. `StatusHandler`, however, applies the event to **every** `Commit` record in the entire Shipit database that shares the reported `sha`, with no check that the commit's stack/repository belongs to the organization that was actually authenticated.

### Finding Description
The webhook trust boundary is enforced once, at the controller level: [1](#0-0) 

`verify_signature` resolves `github_app = Shipit.github(organization: repository_owner)` and checks the HMAC signature using that organization's `webhook_secret`. This proves only that the sender knows the secret configured for **one** organization/app installation — it says nothing about which repository/commit the payload is allowed to affect.

The `create` action then hands the raw JSON `params` straight to the handlers with no further repository scoping at the dispatch layer: [2](#0-1) 

`StatusHandler#process` uses only the `sha` field to look up commits, across the whole `Commit` table, and mutates each match: [3](#0-2) 

There is no `repository`/`organization` requirement in the handler's `params` block, and no filter tying the located `Commit` back to a stack owned by `repository_owner`. Contrast this with `MembershipHandler`, which explicitly requires and uses `params.organization.login` to scope the team it creates/modifies: [4](#0-3) 

**Binding that is broken:** `organization authenticated by verify_signature` ≠ `repository/commit whose status record is written by StatusHandler`. Signature verification binds trust to *the organization owning the payload's declared repository*; the write performed by `StatusHandler` binds only to *a raw SHA string*, which can legitimately collide across repositories that share commit history (forks, template repos, mirrors, or any two stacks tracking overlapping history) — all of which can coexist on a single Shipit instance since stacks are independent per-repository/per-environment records.

### Impact Explanation
An organization/app installation that is legitimately validated by its own `webhook_secret` (i.e., a real but unprivileged-relative-to-other-repos GitHub App installation on *its own* org) can emit a crafted `status` webhook whose `sha` matches a commit that also exists in a **different** repository/stack tracked by the same Shipit instance. Because `StatusHandler` writes a `Status` to every `Commit` row with that SHA regardless of owning repository, the attacker can fabricate a passing CI status (`state: success`, matching `ci.require` context) on a commit belonging to a stack outside their authenticated organization. If that stack has continuous deployment enabled and depends on the forged status context, this results in an **unauthorized deploy on a repository the attacker does not own** — a cross-repository write, matching the report's "Critical" bucket (unauthorized deploy).

### Likelihood Explanation
Exploitation requires: (1) the attacker controls a repository whose webhook is registered with Shipit (i.e., they own/administer some org with a valid Shipit GitHub App installation — not a privileged Shipit account, session, or token), and (2) a commit SHA collision with a target stack's tracked repository, which is realistic when Shipit tracks forks, mirrors, or repositories that share history (a common real-world topology, e.g. release/staging mirrors of the same codebase). This is a design gap rather than a cryptographic collision requirement, so likelihood is Medium: it depends on the deployment tracking related/forked repositories, but the code path itself has zero repository-scoping and will accept it whenever the SHA coincides.

### Recommendation
Scope `StatusHandler` (and audit other handlers for the same pattern) to only touch commits whose `stack.repository` matches the authenticated `repository`/`organization` from the webhook payload, e.g. join through `Stack` and filter by `repo_name`/`repo_owner` derived from `params.repository` before calling `commit.create_status_from_github!`. Require and validate a `repository` field in the handler's `params` schema analogous to how `MembershipHandler` requires `organization`.

### Proof of Concept
1. Attacker registers/owns `org-attacker/some-repo` as a Shipit stack; Shipit's app is installed there with its own `webhook_secret`, which the attacker legitimately possesses (their own installation secret — no compromise of Shipit's credentials needed).
2. Victim stack `org-victim/target-repo` tracks a repository that shares commit history with `org-attacker/some-repo` (fork/mirror/template scenario), so a commit SHA `abc123...` exists identically in both repos' commit tables in Shipit.
3. Attacker sends a `status` webhook to `/webhooks`, signed with their own valid `webhook_secret`, with body `{"sha": "abc123...", "state": "success", "context": "<ci.require context>", "repository": {"owner": {"login": "org-attacker"}}}`.
4. `verify_signature` passes (signature is valid for `org-attacker`'s app). `StatusHandler#process` executes `Commit.where(sha: "abc123...")`, which returns the matching commit row belonging to `org-victim/target-repo`, and calls `create_status_from_github!`, writing a forged success status onto the victim's commit.
5. If `org-victim/target-repo`'s stack has continuous deployment gated on that `ci.require` context, this forged status can trigger an unauthorized deploy.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L15-21)
```ruby
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
```
