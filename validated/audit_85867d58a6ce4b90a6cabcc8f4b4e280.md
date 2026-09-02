### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but `StatusHandler` writes commit statuses using only `sha` with no repository scoping - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC against based on `repository.owner.login`, a plain field inside the same JSON body being verified. The signature therefore only proves "this body was signed with organization X's secret" - it proves nothing about any other field in the payload, including `repository.full_name` or `sha`. Most handlers (e.g. `PushHandler`) at least re-scope to a `Repository` via `repository.full_name` before acting, but `StatusHandler` looks up the target `Commit` purely `Commit.where(sha: params.sha)`, with no repository/organization scoping at all. An attacker who legitimately administers a GitHub App installation for their own onboarded organization (and therefore knows that organization's `webhook_secret`) can forge a `status` event that authenticates as "their org" but writes a status onto a commit belonging to a completely different organization's stack.

### Finding Description
`verify_signature` picks the `GitHubApp` instance to use for HMAC verification from the untrusted payload itself: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` just HMACs the raw request body against the secret belonging to whichever organization was picked above: [3](#0-2) 

This creates the binding break analogous to H-14 ("fee receiver's share used where the pool's share was intended"): here, "the organization that authenticated" (`repository.owner.login`, used only to pick the secret) is treated as equivalent to "the repository/commit that gets written to," when in fact nothing cryptographically ties `owner.login` to any other field in the same JSON body.

Base `Handler` at least tries to re-scope by looking up `Repository.from_github_repo_name(repository_name)` using `repository.full_name`: [4](#0-3) 

`PushHandler` uses that repository-scoped `stacks` relation: [5](#0-4) 

But `StatusHandler` bypasses all of that scoping and looks up commits globally by SHA across the entire Shipit instance: [6](#0-5) 

So the equality this vulnerability breaks is:
`organization authenticated by verify_signature (repository.owner.login)` == `stack/repository actually mutated by StatusHandler (commit found by bare sha, no owner check)`

Before the attacker's request: this equality only holds because a real GitHub webhook always sets `repository.owner.login` and delivers only for the org that installed the app, and GitHub is the only party able to produce a valid signature for that org's secret.

After a crafted request from an attacker with knowledge of Organization A's `webhook_secret` (a legitimate secret for a different tenant/org onboarded onto the same Shipit instance): `repository.owner.login = "OrgA"` (correctly signed with OrgA's secret, so `verify_signature` passes) while `sha` is set to a commit SHA belonging to a stack under Organization B. `StatusHandler` finds and updates `Commit` records purely by `sha`, with no check that the commit's repository/organization matches OrgA.

### Impact Explanation
Commit statuses recorded via `create_status_from_github!` feed into Shipit's deploy-gating logic (required status checks used by `Stack`/`Deploy`/`DeploySpec` to decide whether a commit is deployable). By forging a "success" status (with attacker-chosen `context`, `description`, `target_url`) onto a target commit in another organization's stack, an attacker who controls only their own organization's webhook secret can satisfy CI-check requirements for a stack they have no access to, enabling an unauthorized deploy of that stack. This meets the Critical bar of "unauthorized deploy" without requiring any credential belonging to the victim organization.

### Likelihood Explanation
Requires only: (1) the attacker administers or has access to the webhook secret of any single organization already configured on the shared Shipit instance (a normal, legitimate tenant credential, not the victim's), and (2) knowledge of a target commit SHA in another org's repository (trivially obtainable from public git history, CI logs, or PRs). The webhook endpoint is unauthenticated aside from the signature check, and no additional session, API token, or GitHub write access is required.

### Recommendation
Bind the verified organization to the actual entity being written: after determining `repository_owner` from the (still-unverified) payload and validating the signature, re-derive/validate that `repository.full_name`'s owner segment matches `repository_owner`, and have `StatusHandler` (and any other handler that looks up records without going through `Handler#stacks`) scope its `Commit` lookup to `stacks`/`Repository.from_github_repo_name(payload.dig('repository','full_name'))` rather than a bare, cross-tenant `sha` lookup.

### Proof of Concept
1. Attacker administers Organization A's GitHub App installation on the shared Shipit instance and knows OrgA's `webhook_secret` (`config/secrets.*.yml` shows secrets are per-organization) - [7](#0-6) .
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<sha of a commit belonging to Org B's stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/some-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(OrgA_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` and the HMAC validates against OrgA's real secret, so the request passes - [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the commit under Org B's stack (no owner check), and creates a forged "success" status on it - [6](#0-5) .
6. If Org B's stack requires that status/context for deploy, this can now be deployed by anyone with deploy rights on Org B's stack (or by the same attacker if they also have that access), despite the CI check never having actually run for that commit.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
