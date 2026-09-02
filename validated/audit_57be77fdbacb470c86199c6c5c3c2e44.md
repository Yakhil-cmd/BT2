### Title
Webhook signature scoped to `repository.owner.login` does not bind the organization to the commit/stack actually mutated - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to check against using `repository_owner`, a value read from the attacker-supplied JSON body itself (`repository.owner.login`, falling back to `organization.login`) [1](#0-0) [2](#0-1) . Once the signature is verified against *that* organization's configured secret, the full raw payload is dispatched unchanged to the event handlers, which use a completely different field of the same payload to decide what to mutate. `Shipit::Webhooks::Handlers::StatusHandler#process` looks up records purely by `params.sha` with no repository/organization scoping at all [3](#0-2) . The equality the system implicitly relies on — "the organization whose secret signed this request" == "the repository/commit this request is allowed to mutate" — is never checked.

### Finding Description
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
`repository_owner` is taken straight from the JSON body the attacker controls: `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) . `Shipit::GithubApp#verify_webhook_signature` also short-circuits to `true` whenever that organization has no `webhook_secret` configured, which the setup docs describe as *optional* [4](#0-3) [5](#0-4) .

After this check, `create` hands the entire (attacker-crafted) payload to every registered handler for the event, unmodified: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [6](#0-5) . For the `status` event, `StatusHandler` never re-derives or checks a repository/organization; it acts on every `Commit` in the entire database whose `sha` matches the attacker-chosen value:
```ruby
Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
``` [3](#0-2) 

So the binding broken is: *organization authenticated by the signature* ≠ *stack/commit whose CI status is written*. As long as an attacker can get one signature check to pass — either because they legitimately administer an organization configured in this Shipit instance (with a known secret) or because that organization has no `webhook_secret` set at all — they can submit a `status` webhook naming an arbitrary `sha` that belongs to an entirely unrelated stack/repository and inject a fabricated commit status (e.g. a fake "success" for a required CI context) for it.

### Impact Explanation
Commit statuses created this way feed directly into Shipit's deploy/merge safety gating described in the README (`ci.require`, `ci.blocking`, blocking statuses used to allow/deny deploys and merge-queue admission) [7](#0-6) . Forging a passing status for a commit belonging to a stack/organization the attacker does not control can let a required-CI-status check on someone else's stack be satisfied, contributing to an unauthorized deploy or merge-queue admission for a repository the attacker has no legitimate access to. This satisfies the "unauthorized deploy, rollback or merge" criterion.

### Likelihood Explanation
Exploitation only requires: (1) that this Shipit instance is multi-organization capable (`Shipit.github(organization:)` selects per-organization config), and (2) either possession of one organization's webhook secret (which that organization's own admins legitimately know) or the presence of any configured organization without a `webhook_secret` (explicitly documented as optional). No GitHub write access, Shipit session, or `ApiClient` token is required — the request goes straight to the public `/webhooks` endpoint. The likelihood is therefore tied to the operational choice of leaving `webhook_secret` blank for any org, or to any org-admin abusing their own legitimate secret to target other stacks/orgs hosted on the same Shipit instance — a cross-repository/cross-organization boundary that the code is supposed to, but does not, enforce.

### Recommendation
After signature verification, re-derive the organization/repository from the same trusted field used for signing (`repository.owner.login`/`organization.login`) and enforce that every handler only mutates records (`Commit`, `Stack`, etc.) that belong to that same organization/repository — e.g., have `StatusHandler` and other handlers scope their queries through `Repository`/`Stack` matched to the verified `repository_owner`, rather than a global `Commit.where(sha:)` lookup. Additionally, treat `webhook_secret` as effectively mandatory (or log/alert loudly when absent) since its absence causes `verify_webhook_signature` to unconditionally return `true`.

### Proof of Concept
1. Configure/observe that Shipit is set up for multiple organizations and that organization `attacker-org` either has a known `webhook_secret` (administered by the attacker) or none configured.
2. POST to `/webhooks` with header `X-Github-Event: status` and a signature computed with `attacker-org`'s secret (or no valid secret needed if none is configured), with a body:
```json
{
  "sha": "<sha-of-a-commit-belonging-to-victim-org/victim-repo-stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
3. `verify_signature` verifies the signature against `attacker-org`'s app/secret and passes.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit regardless of `attacker-org` having no relationship to that stack — and calls `create_status_from_github!`, writing a forged status onto the victim's commit [3](#0-2) .

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** README.md (L444-480)
```markdown
<h3 id="ci">CI</h3>

**<code>ci.require</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to disallow deploys if any of them is missing on the commit being deployed.

For example:
```yml
ci:
  require:
    - ci/circleci
```

**<code>ci.hide</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to ignore.

For example:
```yml
ci:
  hide:
    - ci/circleci
```

**<code>ci.allow_failures</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want to be visible but not to required for deploy.

For example:
```yml
ci:
  allow_failures:
    - ci/circleci
```

**<code>ci.blocking</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want to disallow deploys if any of them is missing or failing on any of the commits being deployed.

For example:
```yml
ci:
  blocking:
    - soc/compliance
```
```
