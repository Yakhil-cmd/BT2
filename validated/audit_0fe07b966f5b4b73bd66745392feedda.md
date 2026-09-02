### Title
Webhook signature verification does not bind the authenticated organization to the repository/commit actually written, enabling forged commit statuses across stacks - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` only proves that a request was signed with the secret configured for *some* GitHub organization derived from the unsigned JSON body; it never binds that authenticated organization to the repository or commit that the corresponding `Webhooks::Handlers` actually mutate. `StatusHandler`, in particular, resolves the target purely from `params.sha` with no repository scoping at all, so the value that gets written (an arbitrary commit's CI status) is decoupled from anything that was cryptographically verified. This is the same class of bug as Sherlock M-1: a field that is acted upon (`sha`/commit to update) is never covered by the signature/verification that gates the call.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App config (and thus which `webhook_secret`) to use for HMAC verification based on data taken straight from the unauthenticated request body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as "always verified": [3](#0-2) 

`webhook_secret` is documented as optional, and it is `nil`/unset by default in several shipped configs (development example, test dummy secrets, one entry of the double-org example), so an install that follows the documented setup can legitimately end up with signature verification being a no-op for that organization: [4](#0-3) [5](#0-4) 

Once past `verify_signature`, the controller dispatches the parsed JSON directly to handlers: [6](#0-5) 

Most handlers scope their side effects to a specific repository via `Handler#repository_name`/`#stacks`, which is derived from `payload['repository']['full_name']`: [7](#0-6) 

`StatusHandler`, however, breaks that pattern entirely — it looks up commits by `sha` alone, with no repository/stack filter whatsoever, and writes a status onto every matching `Commit` row in the database: [8](#0-7) 

The trust binding that should hold is:
`verified_organization(secret used to authenticate the request) == owner_of(target Commit/Stack actually mutated)`

Because (a) the organization used to pick the verification secret is read from an unsigned field (`repository.owner.login` / `organization.login`), (b) that secret can be absent/no-op for a configured org, and (c) `StatusHandler` never re-checks the repository of the commit it updates, an unprivileged network attacker who can reach the public `/webhooks` endpoint can craft a `status` event whose `repository_owner` picks a Shipit-configured organization with no (or a leaked/weak) `webhook_secret`, while the `sha`/`state`/`context` fields are chosen to target a commit that actually belongs to a completely different repository/stack tracked by the same Shipit instance.

### Impact Explanation
`Commit#create_status_from_github!` is the mechanism Shipit uses to record CI/check statuses that gate deploy safety (merge/deploy checks rely on these statuses being green). An attacker able to forge or freely send this webhook can mark an arbitrary commit on an arbitrary stack as passing (`state: success`) regardless of which organization/repository the request nominally authenticates against, which can lead directly to an unauthorized deploy of unreviewed/unsafe code — this matches the "Critical: unauthorized deploy" and "cross-repository writes" impact categories, since the write is not bound to the repository that was (or wasn't) authenticated.

### Likelihood Explanation
The `/webhooks` endpoint is intentionally public and unauthenticated by design (it's the GitHub webhook receiver), so no Shipit session, API token, or GitHub write access is required to reach it — only network access to the instance. The only gate is `verify_signature`, and that gate is a documented no-op whenever an organization's `webhook_secret` is left unset (an explicitly supported, "optional" configuration), or trivially satisfiable if an attacker can obtain/guess the secret for any one of the (possibly many, in multi-org installs) configured organizations. Given `StatusHandler` performs zero repository scoping, exploiting the mismatch requires no additional conditions beyond having *any* usable organization key.

### Recommendation
- In `StatusHandler#process`, scope the `Commit` lookup to commits belonging to `stacks`/`repository_name` derived from the payload, mirroring the pattern already used by `Handler#stacks`, instead of a bare `Commit.where(sha: params.sha)`.
- In `GitHubApp#verify_webhook_signature`, do not silently treat an absent `webhook_secret` as "verified"; require an explicit, documented opt-out, or refuse to process events for organizations without a configured secret.
- Bind the organization used for signature verification to the repository owner actually referenced by the handler's write path (e.g., re-validate that `repository.full_name`'s owner matches the `repository_owner` used to select the verifying secret) so the authenticated identity and the mutated resource are the same value.

### Proof of Concept
1. Configure (or find an existing) Shipit multi-org deployment where at least one configured GitHub organization, `OrgWithoutSecret`, has `webhook_secret` unset (a documented, supported configuration, see `docs/setup.md`/`config/secrets.development.example.yml`).
2. As an unauthenticated network client, `POST /webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "OrgWithoutSecret" }, "full_name": "OrgWithoutSecret/unrelated-repo" },
  "sha": "<sha of a commit belonging to victim-org/victim-repo tracked by this Shipit instance>",
  "state": "success",
  "context": "ci/required-check"
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required, because `Shipit.github(organization: "OrgWithoutSecret")` resolves to a `GitHubApp` whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally.
3. `WebhooksController#create` dispatches to `StatusHandler`, whose `process` method runs `Commit.where(sha: params.sha)` — matching the victim commit regardless of the `repository` field in the payload — and calls `commit.create_status_from_github!(params)`, writing a forged "success" status onto a commit in `victim-org/victim-repo`, a stack the attacker has no legitimate authorization over.

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

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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
