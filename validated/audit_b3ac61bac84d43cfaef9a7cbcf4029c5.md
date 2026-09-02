Confirmed: `Handler#repository_name` resolves the target repository from `payload.dig('repository', 'full_name')` [1](#0-0) , while `WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate against using a different field, `repository_owner`, i.e. `params.dig('repository', 'owner', 'login')` (or `organization.login`) [2](#0-1) [3](#0-2) . This is exactly the "organization that authenticated versus the repository that is written" binding.

### Title
Webhook signature is verified against `repository.owner.login`, but the sync target is resolved from a different field `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports hosting multiple GitHub Apps/organizations, each with its own `webhook_secret` [4](#0-3) . `Shipit.github(organization:)` looks up the app config per-organization and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization's `webhook_secret` is blank/unset [5](#0-4) . The controller picks the organization used for verification from `repository.owner.login` (payload field A), but the handler that actually performs the write (finding stacks and enqueuing a sync/build) uses `repository.full_name` (payload field B) — a different field with no guarantee that both refer to the same GitHub org/repo [3](#0-2) [1](#0-0) .

### Finding Description
In a multi-org deployment, `Shipit.github_app_config(organization)` is looked up by whichever organization is present in `repository.owner.login` (or `organization.login`) in the JSON body [6](#0-5) , and the signature is checked against that org's `webhook_secret`. If any configured org has no `webhook_secret` set (a supported and even exemplified configuration, see `test/dummy/config/secrets_double_github_app.yml` and `config/secrets.development.shopify.yml`), `verify_webhook_signature` short-circuits to `true` for any payload claiming that org, regardless of the actual signature header value [7](#0-6) .

The payload's `repository.owner.login` (used to select the authenticating org/secret) is never cross-checked against `repository.full_name` (used to select which `Repository`/`Stack` records get acted on) [1](#0-0) . An attacker can therefore submit a single JSON body where `repository.owner.login` is set to the unsecured organization (bypassing signature verification) while `repository.full_name` is set to `secured-org/some-repo`, a repository that belongs to a different, properly-secreted organization. The `push` handler will resolve `Repository.from_github_repo_name(repository_name)` from that spoofed `full_name` and enqueue `stack.sync_github(expected_head_sha: params.after)` for the real, secured stack [8](#0-7) , without ever presenting a valid signature for that org's secret.

Equality that should hold but doesn't:
`organization used to authenticate (repository.owner.login)` == `repository whose Stack/Repository records get written (repository.full_name)`

### Impact Explanation
This lets an unprivileged external attacker who knows (a) that a target org has no `webhook_secret` configured and (b) the `full_name` of a stack belonging to another (secured) org, forge an unauthenticated `push` webhook that triggers `GithubSyncJob` against the secured stack, causing Shipit to fetch and append attacker-influenced `expected_head_sha` and re-sync commits for that repository — an unauthorized deploy-pipeline action performed without ever satisfying the targeted org's HMAC signature check. This crosses the "authenticated organization vs. repository written" trust boundary and can lead to unauthorized triggering of sync/deploy activity (High, escalation past authentication for a stack's write path).

### Likelihood Explanation
Requires a multi-org Shipit deployment where at least one configured GitHub org omits `webhook_secret` — a configuration explicitly documented and shipped as an example (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`) — combined with knowledge of another stack's `owner/name`. Given `webhook_secret` is documented as "optional" per app instead of mandatory-once-multi-org-is-enabled, this is a realistic operator configuration, making likelihood moderate rather than purely theoretical.

### Recommendation
In `WebhooksController#verify_signature`, derive the authenticating organization from the same field used later for repository resolution (`repository.full_name`'s owner segment), and additionally, reject webhook payloads where `repository.owner.login` does not match the owner segment of `repository.full_name`. Alternatively, require (and refuse to boot without) a `webhook_secret` for every configured organization so `verify_webhook_signature` can never short-circuit to `true`.

### Proof of Concept
1. Configure Shipit with two orgs: `OrgA` (no `webhook_secret`) and `OrgB` (secret set), each hosting stacks, e.g. `OrgB/critical-repo` tracked by Shipit.
2. POST to `/webhooks` with header `X-Github-Event: push`, no/garbage `X-Hub-Signature`, and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/critical-repo"
  }
}
```
3. `verify_signature` looks up `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally [7](#0-6) , and the request proceeds.
4. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgB/critical-repo")` [1](#0-0)  and calls `stack.sync_github(expected_head_sha: params.after)` for `OrgB`'s stack [8](#0-7) , i.e. an unauthenticated actor triggered a sync against a webhook-secret-protected org's stack.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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
