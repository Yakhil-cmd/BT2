## Analysis Result

This confirms the vulnerability: `WebhooksController#verify_signature` selects which GitHub App/webhook secret to check against using `repository_owner` — derived from the attacker-controlled `params.dig('repository', 'owner', 'login')` (or `organization.login`) fallback — while every `Handler` (`PushHandler`, etc.) subsequently resolves the actual repository to act on via `payload.dig('repository', 'full_name')`. These two fields are never cross-validated against each other, and both come from the same untrusted JSON body.

### Title
Webhook organization used for signature selection is not bound to the repository `full_name` actually acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the webhook secret) to validate against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` with a fallback to `params.dig('organization', 'login')` [1](#0-0) . Every registered `Handler` subclass, however, determines the actual repository/stacks to mutate using a *different* field of the same payload: `payload.dig('repository', 'full_name')` [2](#0-1) . Nothing enforces that `repository.owner.login` (used to choose the signing secret) matches the owner encoded in `repository.full_name` (used to choose the repository that is actually written to).

### Finding Description
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [3](#0-2) 

Crucially, `GitHubApp#verify_webhook_signature` treats an unset (nil/optional) webhook secret as automatically verified:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

The setup documentation explicitly states the webhook secret is optional per configured organization: *"Webhook secret (optional): Fill it with some randomly generated string..."* [5](#0-4)  and Shipit explicitly supports multiple independently-configured GitHub organizations sharing one Shipit install [6](#0-5) .

The equality that should hold is:
`organization that authenticated the request (repository.owner.login)` == `organization implied by the repository that gets written (repository.full_name)`

Before the attacker's request, in the legitimate flow both fields are populated consistently by GitHub itself, so this equality always holds. After the attacker's forged request, the attacker sets `repository.owner.login` to any org configured in Shipit that has **no** `webhook_secret` set (satisfying `verify_webhook_signature` trivially, with **no secret knowledge required**), while setting `repository.full_name` to `"other-org/victim-repo"` — a completely different, secret-protected organization/repository whose stacks exist in the same Shipit instance. `PushHandler#process` (and any other handler) will resolve `stacks` via `Repository.from_github_repo_name(repository_name)` using the forged `full_name`, and act on it — e.g., enqueuing `GithubSyncJob` with an attacker-chosen `expected_head_sha` [7](#0-6) , or completely bypassing the org boundary for `membership`/`pull_request`/`status` handlers that also key off `payload.dig('repository','full_name')`.

### Impact Explanation
An attacker who has never had any credential for the victim organization, and is not required to know `webhook_secret`, `api_clients_secret`, or hold a Shipit session, can trigger writes (sync jobs, stack state changes, potentially fake status/check-run ingestion feeding into merge-queue/deploy decisions) for a repository/organization they have no authorization over — purely by knowing that the target Shipit instance also serves at least one other, secret-less-configured organization. This crosses the "organization that authenticated versus the repository that is written" trust boundary called out explicitly in scope, and can lead to unauthorized state changes/cross-repository writes (e.g., forged push/status events causing an unintended deploy decision).

### Likelihood Explanation
This requires no privileged credential: it only requires (a) the target Shipit deployment to host multiple GitHub organizations, one of which the operator left `webhook_secret` unset (explicitly documented as optional, so a realistic real-world configuration), and (b) attacker knowledge of a target repo's `full_name`, which is public information. No secrets, tokens, or sessions are needed — this is a pure unprivileged HTTP POST to `/webhooks`.

### Recommendation
Bind the two identifiers together and re-verify after parsing: derive the signing organization the same way the handler derives the acted-upon repository (i.e., always use `repository.full_name`'s owner segment, not `repository.owner.login`/`organization.login`, for the `Shipit.github(organization:)` lookup), or explicitly assert `repository.owner.login == repository.full_name.split('/').first` before dispatching to handlers. Additionally, consider making `webhook_secret` mandatory for any multi-organization deployment, since "no secret configured" degrades to a bypass rather than a graceful default.

### Proof of Concept
1. Shipit instance configured with two orgs: `OrgA` (no `webhook_secret` set) and `OrgB` (has `webhook_secret` set, hosts stack `OrgB/victim-repo`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. `verify_signature` computes `repository_owner = "OrgA"`, loads `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally regardless of the (missing/arbitrary) `X-Hub-Signature` header [8](#0-7) .
4. `WebhooksController#create` dispatches to `PushHandler.call(params)`, which resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` [2](#0-1)  and enqueues a `GithubSyncJob` for `OrgB`'s stack using attacker-supplied `expected_head_sha` [7](#0-6)  — despite the request never being authenticated against `OrgB`'s secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
