### Title
Organization-fallback signature selection lets one tenant's webhook secret authenticate a `push` for a *different* repository's stack, driving unauthorized `PushHandler#process` / `sync_github` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/push_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to validate against using `repository_owner`, which falls back from `repository.owner.login` to `organization.login` when the payload omits the former. Every handler (including `PushHandler`) instead resolves the target repository/stack from `payload.dig('repository', 'full_name')` in `Handler#repository_name`. Because these are two independently attacker-controlled JSON fields, a request signed with one organization's known webhook secret can be crafted to name a repository belonging to an entirely different organization, letting `PushHandler` sync (and potentially deploy) a stack it never authenticated against.

### Finding Description
The invariant that should hold is:

`organization_that_authenticated(request) == organization_that_owns(repository_name_used_by_handler)`

i.e. the org whose secret validated `X-Hub-Signature` must be the same org that owns `payload.dig('repository','full_name')`.

Trace:
- `verify_signature` picks the verifier via `repository_owner`, defined as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and uses it to fetch `Shipit.github(organization: repository_owner)` before calling `github_app.verify_webhook_signature` [2](#0-1) .
- `verify_webhook_signature` computes/compares an HMAC over the *raw* request body against that specific organization's configured `webhook_secret` [3](#0-2) .
- Every handler's `process` acts on stacks resolved via `Handler#stacks`, which loads `Repository.from_github_repo_name(repository_name)` where `repository_name` is `payload.dig('repository', 'full_name')` — a completely different field than the one used for authentication [4](#0-3) .
- `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack matching `branch` (derived from `params.ref`) for that resolved repository [5](#0-4) .

Exploit flow: an attacker who is an admin/owner of Organization A onboarded to the same multi-tenant Shipit instance (and therefore knows/controls Org A's webhook secret configured for their own GitHub App/webhook) crafts a raw POST body such as:
```json
{
  "ref": "refs/heads/master",
  "after": "<any 40-hex sha>",
  "repository": { "full_name": "victim-org/victim-repo" },
  "organization": { "login": "org-a" }
}
```
They omit `repository.owner.login` so `repository_owner` falls back to `organization.login` = `"org-a"`. They compute `X-Hub-Signature` using Org A's known secret. `verify_signature` picks Org A's `GitHubApp`, and the signature checks out — the request is "verified." But `Handler#repository_name` reads `repository.full_name` = `"victim-org/victim-repo"`, which is unrelated to Org A, and `PushHandler` calls `sync_github` on that victim stack, regardless of its `review_stacks_enabled` setting (this handler does not consult that flag at all — it applies uniformly to every non-archived stack matching the branch, review stack or not).

Existing guards do not prevent this: `verify_signature` never cross-checks that the org it authenticated against matches the org embedded in `repository.full_name`; `drop_unhandled_event` only checks the event type is registered; there is no `ExplicitParameters` validation tying `repository.full_name`'s owner segment to `repository_owner`.

### Impact Explanation
A payload authenticated under one tenant's (Organization A's) webhook secret can mutate/sync a stack belonging to a completely unrelated repository/organization ("victim-org/victim-repo") — this is "a payload for one repository mutating another's stack," a Critical-severity category. `sync_github` can advance the stack's deployed/undeployed commit state and, depending on stack configuration (continuous delivery, auto-merge/auto-deploy), drive further automated deploy/rollback actions on the deploy host. The blast radius spans every repository/org hosted on the same Shipit instance whose webhook secret differs from the victim's, i.e., cross-tenant. Note: `review_stacks_enabled` is irrelevant to `PushHandler` specifically (it is only consulted by the PR `opened`/`reopened`/`labeled`/`unlabeled` handlers to decide whether to auto-provision review stacks) — `PushHandler` syncs any stack, review or non-review, so the actual exposure here is broader than "review stacks," not narrower.

### Likelihood Explanation
Preconditions: Shipit must be configured to serve multiple organizations (multiple `github_apps`/webhook-secret entries), and the attacker must control (or know the secret for) at least one onboarded organization — a realistic scenario for shared/self-hosted multi-tenant Shipit deployments where different teams each configure their own GitHub App/webhook secret. Given that, forging the request costs only an HTTP POST with a correctly computed HMAC; no GitHub session, API token, or victim secret is required. It is fully repeatable against any repository/stack hosted on the same instance as long as the attacker knows the branch name.

### Recommendation
Bind authentication to the same field used for resolving the target: derive `repository_owner` strictly from `repository.full_name`'s owner segment (or `repository.owner.login`) — never fall back to the independently-controlled `organization.login` for signature-org selection — or, after verifying, explicitly assert that the authenticated organization equals the owner segment of `payload.dig('repository','full_name')` before invoking any handler, rejecting the event (422) on mismatch.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (using the existing multi-org fixture `test/dummy/config/secrets_double_github_app.yml`):
1. Configure two orgs, `org-a` (attacker-known secret) and `victim-org` (a different secret the attacker does not know), matching the double-github-app fixture.
2. Create a non-archived `Stack` for repository `victim-org/victim-repo` with `branch: "master"` and `review_stacks_enabled: false`.
3. Build a push payload: `{"ref"=>"refs/heads/master", "after"=>"a"*40, "repository"=>{"full_name"=>"victim-org/victim-repo"}, "organization"=>{"login"=>"org-a"}}` (no `repository.owner.login`).
4. Sign the raw JSON body with `org-a`'s webhook secret and set it as `X-Hub-Signature`; set `X-Github-Event: push`.
5. POST to `/webhooks`; assert response is `200 OK` (verification passed under `org-a`).
6. Assert (via mock/spy) that `Stack#sync_github` was invoked with `expected_head_sha: "a"*40` on the `victim-org/victim-repo` stack — i.e., the equality `organization_that_authenticated == organization_that_owns(repository.full_name)` is false (`"org-a" != "victim-org"`) yet the sync still executed, proving the binding is broken.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
```
