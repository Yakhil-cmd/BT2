### Title
Cross-repository commit status injection via unscoped `sha` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The `status` webhook handler writes a commit status using only the `sha` from the payload, with no check that the `sha` belongs to the repository/organization that was actually authenticated by `verify_signature`. This breaks the binding "organization authenticated == repository written," and lets a GitHub App owner for *any* organization configured on the Shipit instance inject a status onto a commit belonging to a *different* tracked repository, potentially unblocking deploys/merges that depend on that status.

### Finding Description
`WebhooksController#verify_signature` picks the signing secret to validate against based on `repository_owner`, derived from the payload itself (`params.dig('repository','owner','login') || params.dig('organization','login')`): [1](#0-0) [2](#0-1) 

This only proves the request was signed with the webhook secret belonging to whatever organization the *attacker chooses to put in the payload* — it says nothing about which repository's data will actually be mutated. Every other handler (`Handler#stacks`) at least re-derives scope from `repository.full_name` before acting: [3](#0-2) 

But `StatusHandler#process` never calls `stacks`/`repository_name` at all — it looks up commits globally by `sha` across the entire installation and writes a status to every match: [4](#0-3) 

So the equality that should hold is: `organization authenticated by verify_signature (repository.owner.login in the payload)` == `repository whose commit receives the status write (implied by sha)`. `StatusHandler` never enforces the right-hand side at all — the `repository` field in the payload is only used to pick which webhook secret validates the signature, then discarded. Any commit `sha` in the payload, regardless of which repo it came from in the signed payload's `repository` object, gets matched against `Commit.where(sha: ...)` for the whole database.

Since a Shipit instance can be configured with multiple GitHub Apps for multiple organizations (as documented in `test/dummy/config/secrets_double_github_app.yml`), an attacker who controls (or is a legitimate, lower-trust member of) one organization's GitHub App/webhook secret can send a validly-signed `status` event whose `repository.owner.login` is their own org (so it passes `verify_signature`), but whose `sha`/`state`/`context` target a commit that actually belongs to a completely different, victim organization's stack tracked by the same Shipit instance. Commit SHAs are not secrets — they are visible on GitHub, in Shipit's own UI, and in PR/commit metadata — so an attacker can trivially obtain the SHA of a commit they want to unblock.

### Impact Explanation
Shipit's deploy pipeline and merge queue rely on required/blocking commit statuses (`Shipit::Status`, `DeploySpec` required/blocking statuses, `MergeRequest` revalidation) to decide whether a commit is safe to deploy or merge. Forging a `success` status on an arbitrary commit belonging to another repository can satisfy those requirements and trigger an unauthorized deploy or merge for a stack the attacker has no legitimate access to — this maps to the "unauthorized deploy, rollback or merge" Critical impact category.

### Likelihood Explanation
Exploitation requires only (a) the attacker to be able to sign a webhook for *some* organization configured on the target Shipit instance (any org whose GitHub App/webhook_secret they hold, which multi-tenant Shipit deployments explicitly support), and (b) knowledge of a target commit SHA in another tracked repository, which is public information. No repository write access, Shipit session, or `ApiClient` token is needed — only a webhook secret for an unrelated, attacker-controlled organization.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository implied by the authenticated payload (e.g., join through `stacks`/`Repository.from_github_repo_name(repository_name)` as `Handler#stacks` already does for other handlers) instead of a bare global `Commit.where(sha: params.sha)`, so a status can only be applied to commits belonging to the same repository that was cryptographically authenticated by `verify_signature`.

### Proof of Concept
1. Shipit is configured with two GitHub Apps: one for `victim-org` (tracking `victim-org/app`, with commit `abc123` needing a green "ci/tests" status to be deployable) and one for `attacker-org` (which the attacker controls, per `secrets_double_github_app.yml`-style multi-org config).
2. Attacker crafts a `status` webhook payload:
```json
{
  "sha": "abc123",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
3. Attacker signs the payload with `attacker-org`'s webhook secret and sends it to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, verifies successfully against `attacker-org`'s secret [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: 'abc123')` — matching the victim's commit in `victim-org/app` — and calls `create_status_from_github!`, marking it green with no verification the signed org owns that commit [4](#0-3) .
6. `victim-org/app`'s stack now sees a fabricated passing status on `abc123`, potentially permitting an unauthorized deploy.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
