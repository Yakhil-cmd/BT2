### Title
Webhook signature verification is scoped to `repository.owner.login`, but event processing trusts an unbound `repository.full_name` / commit `sha`, allowing cross-organization/cross-repository status and sync forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`SkinnyOptimisticOracle`'s bug was invoking a callback on the wrong bound address (proposer instead of requester) — i.e., the code trusted one identity to act on behalf of another that was never actually verified for that action. The same class of bug exists in Shipit's webhook pipeline: the HMAC signature check binds a webhook to *one* GitHub organization (`repository.owner.login`), but the code that actually mutates state trusts a *different*, uncorrelated field from the same untrusted JSON body (`repository.full_name`, or in the `status` handler, a bare `sha` with no repository scoping at all).

### Finding Description
`WebhooksController#verify_signature` selects which configured GitHub App/organization's `webhook_secret` to validate the HMAC signature against using: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

with `repository_owner` derived from: [2](#0-1) 

Once the signature is accepted for that organization, `create` dispatches the *entire raw JSON body* to handlers with no further scoping to that organization: [3](#0-2) 

Each handler resolves the target `Repository`/`Stack` from a *different, independent* field of the same attacker-controlled payload — `repository.full_name` — never cross-checked against `repository.owner.login`: [4](#0-3) 

`StatusHandler` is worse: it doesn't scope by repository at all, it matches by bare commit `sha` across the entire Shipit instance: [5](#0-4) 

This is exactly the "organization that authenticated versus the repository that is written" binding break: Shipit's `github.<org>.webhook_secret` config (documented for multi-organization installs) is meant to attest "this payload came from GitHub for organization X," but nothing enforces that the repository/commit acted upon by the handler actually belongs to organization X.

**Attack scenario:** Shipit is configured (per `docs/setup.md`, "Using Multiple Github Applications") with several GitHub Apps, one per organization, each with its own `webhook_secret`: [6](#0-5) 

An unprivileged attacker who legitimately owns/administers **one** of these organizations (and therefore legitimately knows that org's `webhook_secret`, e.g. by creating their own GitHub App/organization that a shared Shipit instance has been configured to trust, or replaying that org's real webhook traffic) can POST directly to `/webhooks` a self-crafted JSON body where:
- `repository.owner.login` == attacker's own organization (so `Shipit.github(organization: repository_owner)` picks the attacker's own, legitimately-known `webhook_secret`, and `verify_webhook_signature` — a straightforward HMAC-SHA1 check over the raw body — passes: [7](#0-6) )
- `repository.full_name` == a victim organization's tracked repository name, or (for `status` events) `sha` == a victim commit's SHA in a completely unrelated repository/stack.

Because the signature check never inspects `repository.full_name` or `sha` for consistency with `repository.owner.login`, the forged event is accepted and dispatched to handlers that operate on the victim's `Stack`/`Commit` records.

### Impact Explanation
- `status` event → `StatusHandler#process` creates a passing/forged `Status` on **any commit in any repository tracked by the whole Shipit instance**, purely by SHA match, with zero binding to the authenticating organization. Shipit's merge/deploy gating relies on commit statuses/check runs (`CommitChecks`, `Status::Group`) to decide whether a commit is safe to merge/deploy. Forging a green status on a victim's commit can help push through an unauthorized merge or deploy for a repository the attacker has no access to.
- `push` event → enqueues `GithubSyncJob` for whatever stack matches the forged `repository.full_name`, causing Shipit to sync/process a ref update on a repository/organization the attacker never authenticated for.
- `check_suite` event → enqueues `RefreshCheckRunsJob` against a victim stack based on the same unbound `full_name`.
- `pull_request` handlers (open/close/label/etc.) similarly act on `Repository.from_github_repo_name(repository_name)` for any repo, regardless of which org's secret validated the request.

This breaks the intended trust boundary that a webhook signed by organization X's secret should only ever affect data belonging to organization X's repositories, enabling cross-repository/cross-organization writes and potentially an unauthorized deploy — matching the Critical impact bucket ("cross-repository writes, or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires only that the attacker control one legitimately configured GitHub organization/App in a multi-organization Shipit deployment (a documented, supported configuration) and be able to craft an arbitrary raw HTTP POST to the public `/webhooks` endpoint — no Shipit session, `ApiClient` token, or GitHub write access to the victim repository is needed. The signature scheme (per-organization HMAC secret) is fundamentally decoupled from per-repository/per-commit authorization, so exploitation is a matter of constructing a payload rather than defeating cryptography.

### Recommendation
After signature verification succeeds for organization `repository_owner`, re-validate that the repository actually referenced in the payload (`repository.full_name`) belongs to that same organization (e.g., assert `repository.full_name.split('/').first == repository_owner`) before dispatching to handlers, and scope `StatusHandler#process` (and any other handler) to commits/stacks belonging to repositories owned by the authenticated organization rather than matching globally by `sha`.

### Proof of Concept
1. Configure/observe a multi-org Shipit instance as in `docs/setup.md` with orgs `attacker-org` and `victim-org`, each with independent `webhook_secret`s.
2. As the legitimate admin of `attacker-org`'s GitHub App (attacker-controlled, no privileges on `victim-org`), craft:
```json
{
  "sha": "<victim commit sha in victim-org/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {
    "full_name": "attacker-org/whatever",
    "owner": { "login": "attacker-org" }
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(attacker-org_webhook_secret, raw_body)>` (a secret the attacker legitimately knows).
4. POST to `/webhooks` with header `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` = `attacker-org`, verifies against `attacker-org`'s secret, and passes.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a `Status` on the victim commit in `victim-org/victim-repo`, a repository/organization the attacker never authenticated against — [5](#0-4) .

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
