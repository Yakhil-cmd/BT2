### Title
Webhook organization used to select the signing secret is never bound to the repository the event data actually writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/webhook secret to verify a request against by reading an unauthenticated field out of the raw JSON body (`repository.owner.login`, falling back to `organization.login`), before the signature has been checked. The handlers that subsequently execute the event, however, resolve the *actual* repository/commit to mutate from other, independent fields of that same unauthenticated body (`repository.full_name` for most handlers, and for `StatusHandler`, nothing at all — it looks up commits globally by `sha`). Nothing ties the organization that was used to authorize the request to the repository/commit that is actually written, so if any single configured organization in the deployment has no `webhook_secret` set (a state explicitly documented as supported/optional), that organization's "always-verified" identity can be used to push writes into any other, properly-secured organization's stacks.

### Finding Description
`verify_signature` derives the org before verifying anything: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` resolves per-org config, and `verify_webhook_signature` trivially returns `true` whenever that org has no `webhook_secret` configured: [3](#0-2) 

This is a documented, supported configuration (`webhook_secret: # nil`, "optional" in the setup docs), used for multi-org deployments where each org has its own app/secret block: [4](#0-3) 

Once the (weakly- or non-) authenticated request passes, `WebhooksController#create` hands the *entire unauthenticated body* to the handler for the declared event, with no re-derivation or cross-check against `repository_owner`: [5](#0-4) 

Handlers then resolve their write target from other fields of the same forgeable body. `PushHandler`/`CheckSuiteHandler`/etc. resolve the target repository via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`: [6](#0-5) 

`StatusHandler` is worse: it performs no repository binding whatsoever and mutates *any* commit in the entire install that matches the given `sha`: [7](#0-6) 

So the field used to select/authenticate the signing key (`repository.owner.login`/`organization.login`) is never the same field, nor cross-validated against the field(s) used to decide what gets written (`repository.full_name`, or, for statuses, nothing but a global `sha` lookup). This is the direct analog of the reported bug class: a value the system trusts and acts on (the target repository/commit) is never covered by the verification step (the signature check keyed on a *different*, attacker-supplied field of the same unverified payload).

### Impact Explanation
An attacker who knows that one organization configured on the Shipit instance has no `webhook_secret` (or knows of any org config without one — this is visible from documented behavior, not a secret) can send an arbitrary, unsigned/mis-signed webhook body claiming `repository.owner.login`/`organization.login` for that unsecured org, while populating `sha`/`repository.full_name`/`branches` referencing a commit or stack that belongs to a *different*, properly-secured organization. Because `verify_webhook_signature` short-circuits to `true` for the unsecured org, the request passes verification entirely, and the handler then writes state (fake CI/commit statuses via `StatusHandler`, `check_suite` refresh triggers, `push`-triggered syncs, etc.) into a stack that the attacker was never authorized to affect. Since commit statuses are foundational inputs to Shipit's deploy readiness checks, this allows an unauthorized cross-repository write into another organization's deploy pipeline state — matching the Critical "cross-repository writes / unauthorized deploy" category.

### Likelihood Explanation
Requires no possession of any `webhook_secret`, `api_clients_secret`, or GitHub credential — the only precondition is that the operator has configured (per the documented, optional multi-org `github:` block) at least one organization without a `webhook_secret`, which is an explicitly supported configuration rather than a misconfiguration outside the docs. Any attacker capable of sending an HTTP POST to `/webhooks` can then forge a payload; the mismatched-field routing logic itself (owner used for auth vs. full_name/sha used for effect) is unconditional application code, not dependent on any other privilege.

### Recommendation
- After signature verification succeeds for organization `O`, re-derive the target repository strictly from data cryptographically bound to that same verification path, and reject the event if `repository.full_name`'s owner does not match the organization `O` selected for verification.
- For `StatusHandler` (and any other handler using a bare `sha` lookup), scope `Commit.where(sha: ...)` to commits belonging to the repository named/verified for this specific webhook, not to a global lookup across every tracked repository.
- Consider disallowing (or clearly gating with an explicit ops opt-in and warning) `webhook_secret: nil` in any deployment that also hosts stacks belonging to other organizations, since a blank secret degrades verification to a no-op for that org identity.

### Proof of Concept
1. Deploy Shipit with two configured GitHub orgs, e.g. `OrgOne` (no `webhook_secret`) and `OrgTwo` (real `webhook_secret`), each with tracked repositories/stacks — a supported configuration per `docs/setup.md`.
2. Attacker (no credentials, no GitHub App access) sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything-or-omitted

{
  "sha": "<sha of a commit in a OrgTwo-owned stack>",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "OrgOne" } }
}
```
3. `WebhooksController#verify_signature` computes `repository_owner == "OrgOne"`, loads `Shipit.github(organization: "OrgOne")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the (bogus) `X-Hub-Signature`.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the targeted commit that actually belongs to `OrgTwo`'s properly-secured stack — and writes a forged "success" status onto it via `commit.create_status_from_github!(params)`, even though the request was never validated against `OrgTwo`'s real webhook secret.

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

**File:** docs/setup.md (L181-209)
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
