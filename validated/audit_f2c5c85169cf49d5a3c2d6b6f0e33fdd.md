### Title
Webhook signature authenticates the sending organization but `StatusHandler`/`PushHandler` act on repository/commit fields never bound to that organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to verify against using `repository.owner.login` (falling back to `organization.login`) from the JSON body, then hands the *entire, attacker-supplied* body to the matching `Shipit::Webhooks::Handlers::*` handler. Neither `PushHandler` nor `StatusHandler` re-derives or cross-checks that the repository/commit they act on actually belongs to the organization whose secret validated the signature. This breaks the binding: `organization that authenticated == repository/commit that is written`.

### Finding Description
`verify_signature` picks the `GitHubApp` (and thus the `webhook_secret`) to validate against solely from fields inside the same JSON body it is validating: [1](#0-0) [2](#0-1) 

Because Shipit is multi-tenant — `config/secrets.*.yml` lists independent `github:` orgs, each with its own `webhook_secret`, `oauth`, and `teams` — an attacker who legitimately administers *one* configured GitHub App/organization (and therefore knows *that org's* `webhook_secret`) can craft an arbitrary JSON body, set `repository.owner.login` to their own org (so `Shipit.github(organization: repository_owner)` picks their own secret) and HMAC-sign the whole body with that secret. The signature check only proves "this body was signed by someone who knows org A's secret" — it proves nothing about the other fields inside that same body, e.g. `repository.full_name` or `sha`, which the handlers use for actual mutation:

- `Handler#repository_name` (used by `PushHandler`) resolves the target Stack purely via `payload.dig('repository', 'full_name')`, with no comparison to the organization used to select the verifying secret: [3](#0-2) 
- `PushHandler#process` uses that unchecked `full_name` to look up stacks and forces a `sync_github`: [4](#0-3) 
- `StatusHandler#process` is worse: it does not scope by repository/organization at all — it looks up `Commit.where(sha: params.sha)` globally across every stack in the installation and writes a CI status to whatever commit matches that SHA: [5](#0-4) 

So the equality the design implicitly assumes is:
`organization authenticated by verify_signature == repository/commit whose state PushHandler/StatusHandler mutate`

but nothing enforces it — an attacker with a valid secret for org A can put `repository.owner.login: "orgA"` (to pass signature verification) while `repository.full_name` or `sha` refers to a stack/commit belonging to org B, and the handler will act on org B's data anyway.

### Impact Explanation
An attacker who legitimately controls a GitHub App/organization configured in this Shipit instance (i.e., knows only their own org's `webhook_secret`, not a privileged Shipit credential) can:
- Force `PushHandler` to call `stack.sync_github` on any other organization's stacks whose branch name they can guess, and
- Forge `commit_status` events (`StatusHandler`) for arbitrary commit SHAs belonging to unrelated stacks/repositories they have no access to, since the SHA lookup is completely unscoped.

Since commit/deployable status gates automatic merges and deploy eligibility elsewhere in the codebase (`Stack`, `Commit`, `MergeRequest`, `UndeployedCommit` all consume status/CI state), forged statuses for a commit in a repository the attacker does not control can influence merge/deploy gating logic for that unrelated stack — a cross-repository/cross-organization write achieved purely by owning a secret meant to scope only to one's own org. This matches the "authenticated organization vs. repository actually written" boundary called out as in-scope, and rises to the level of unauthorized cross-repository state manipulation.

### Likelihood Explanation
Requires the attacker to control at least one GitHub App/org already configured in the shared Shipit deployment (a realistic scenario for the multi-org config shown in `config/secrets.development.shopify.yml`), plus knowledge of a target commit SHA or stack/branch name (often discoverable via the public Shipit UI or GitHub). No Shipit session, API token, or the target org's own webhook secret is needed — only the attacker's own legitimately-issued secret.

### Recommendation
Do not select the verification secret from attacker-controlled body fields. Instead, either verify against every configured org's `webhook_secret` and only accept the payload if the successfully-verifying org matches the `repository`/`organization` actually referenced by the handler logic, or record which org's secret verified the request and pass that identity to handlers so `PushHandler`/`StatusHandler` can reject any repository/commit that does not belong to the verified organization's installation.

### Proof of Concept
1. Attacker administers `orgA`'s GitHub App on the shared Shipit instance and knows `orgA`'s `webhook_secret`.
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<commit sha belonging to orgB/some-critical-repo>",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/decoy" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(orgA_webhook_secret, body)` and POSTs to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches `orgA`'s `GitHubApp`, and the HMAC validates successfully because the attacker signed with the correct secret for `orgA`. [1](#0-0) 
5. `StatusHandler#process` then executes `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on the matched commit belonging to `orgB`, regardless of the fact only `orgA` was authenticated. [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
