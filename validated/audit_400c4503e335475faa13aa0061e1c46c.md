### Title
Webhook organization-authentication does not bind to the target repository, allowing cross-repository commit-status writes - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` is used to HMAC-verify an incoming webhook based solely on `repository.owner.login` (falling back to `organization.login`) taken from the JSON body itself. [1](#0-0)  Once that signature check passes for *any* configured organization, the resulting payload is dispatched to event handlers that do not re-derive or re-check the repository the signing organization is allowed to act on. In particular, `StatusHandler#process` looks up the target `Commit` purely by `sha`, with no scoping to the repository/organization whose secret validated the request. [2](#0-1)  This is the sandwich-attack bug class analog: the field the signature actually authenticates (`repository.owner.login`/`organization.login`) is disjoint from the field the handler logic actually acts on (the free-form `sha` matched against the entire `Commit` table), breaking the binding `authenticated_organization == repository_written`.

### Finding Description
Shipit supports multi-tenant deployments where multiple independent GitHub organizations each have their own GitHub App installation and their own `webhook_secret` configured under distinct top-level keys in `config/secrets.yml`. [3](#0-2)  `Shipit.github(organization: repository_owner)` picks the `GitHubApp` instance (and thus the secret) purely from the `repository.owner.login` / `organization.login` value present in the untrusted JSON body, then calls `verify_webhook_signature` using that org's secret against the raw POST body. [4](#0-3)  `GitHubApp#verify_webhook_signature` is a straightforward HMAC-SHA1 comparison of the signature against the raw message using the configured secret. [5](#0-4) 

Because each organization onboarded onto the shared Shipit instance knows/controls its own `webhook_secret` (it's configured per-org for their own GitHub App installation), an org that is legitimately onboarded (Org A) can compute a valid signature over an arbitrary JSON body of its choosing, as long as `repository.owner.login` in that body equals `"OrgA"` so that `verify_signature` selects Org A's own secret to validate it.

Once verified, the dispatched handler for the `status` event does not re-check any organization/repository binding:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 
This queries `Commit` globally by `sha` with no join/filter on repository or stack, unlike other handlers (e.g. `PushHandler`, `CheckSuiteHandler`) which at least scope through `stacks` derived from `Repository.from_github_repo_name(repository_name)`. [6](#0-5)  Even for handlers that do use `stacks`, the repository name used to compute `stacks` (`payload.dig('repository', 'full_name')`) is a separate JSON field from the one used for signature-organization selection (`repository.dig('owner','login')`), so nothing enforces that the two agree — the signature only proves "this body was signed by Org A's secret," not "every field referencing a repository inside this body belongs to Org A."

### Impact Explanation
An org onboarded to a shared/multi-tenant Shipit instance can forge a `status` webhook, signed with its own legitimate `webhook_secret`, that writes a `CommitStatus` (e.g. state `"success"`) against a commit `sha` belonging to a completely different organization's/team's repository tracked by the same Shipit instance. This is a direct cross-repository write performed by an entity that was never granted any permission on the victim repository — satisfying the "cross-repository writes" critical-impact category. Since commit statuses are the mechanism Shipit uses to represent CI/checks state on a commit, this also lets the attacking org fabricate passing CI checks on a victim commit, which can influence deploy-readiness signals surfaced to legitimate deployers of the victim stack.

### Likelihood Explanation
Exploitation requires the attacker to control a legitimately onboarded GitHub organization (with its own webhook_secret) on a multi-organization Shipit instance and to send a crafted HTTP POST to the shared `/webhooks` endpoint (a capability an org admin has once GitHub delivers/replays events, or which can be triggered by scripting a signed request using the org's own secret). No access to the victim org, no privileged Shipit account, and no compromise of the victim's credentials is required — only the ability to author webhook payloads for one's own onboarded org, which is a normal, unprivileged capability in this deployment model.

### Recommendation
Bind the verified organization to the entities the handler is allowed to mutate:
- In `WebhooksController`, after verifying the signature, pass the authenticated `repository_owner`/organization down to handlers instead of letting handlers independently trust `payload.dig('repository', 'full_name')` or unscoped identifiers like `sha`.
- In `StatusHandler` (and any other handler), scope lookups through the repository/organization that was cryptographically verified, e.g. `stacks.commits.where(sha: params.sha)` instead of `Commit.where(sha: params.sha)`, so a commit can only be updated if it belongs to a stack whose repository matches the authenticated organization.
- Add a consistency check that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login` used for signature selection, rejecting mismatched payloads.

### Proof of Concept
1. Shipit is configured (per `docs/setup.md`) with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret`, both onboarded to the same Shipit instance. [3](#0-2) 
2. `OrgA` (attacker-controlled) knows its own `webhook_secret` and computes `HMAC-SHA1(webhook_secret_OrgA, body)` over a crafted JSON body:
```json
{
  "sha": "<victim-commit-sha-belonging-to-OrgB-repo>",
  "state": "success",
  "context": "ci/attacker",
  "repository": { "owner": { "login": "OrgA" } }
}
```
3. POST this body to `/webhooks` with header `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgA")` and verifies successfully using `OrgA`'s own secret. [4](#0-3) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` unconstrained by any organization/repository check and calls `create_status_from_github!`, writing a fabricated "success" status onto `OrgB`'s commit despite the request only ever being authenticated as `OrgA`. [2](#0-1)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-36)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
