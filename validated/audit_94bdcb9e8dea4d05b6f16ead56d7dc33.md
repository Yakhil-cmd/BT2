### Title
Webhook signature is validated against the payload's declared organization, but handlers act on an unvalidated repository field, allowing cross-organization stack writes on multi-org Shipit instances - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which HMAC secret to check the GitHub webhook signature against based on `repository_owner`, a value read straight out of the untrusted JSON body (`repository.owner.login` or `organization.login`). Once the signature check passes, `create` dispatches the *entire same payload* to event handlers, but those handlers (e.g. `PushHandler`, via `Handler#repository_name`) resolve the target `Repository`/`Stack` using a *different* field, `repository.full_name`. Nothing re-confirms that `repository.full_name`'s owner matches `repository_owner`. On a Shipit deployment configured for multiple GitHub organizations/apps (as the engine explicitly supports — see `test/dummy/config/secrets_double_github_app.yml` with distinct `webhook_secret` per org), an actor who legitimately controls the webhook secret for OrgA can forge a payload where `repository.owner.login` is `OrgA` (so the signature check passes with OrgA's secret) while `repository.full_name` names a stack owned by an unrelated `OrgB`, causing writes (commit ingestion, statuses, PR/check state, etc.) against OrgB's stacks.

### Finding Description
- Signature verification binding: `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` with that org's `webhook_secret`. [1](#0-0) 
- `repository_owner` is taken from the same attacker-controlled JSON body being verified: [2](#0-1) 
- After the signature check, the raw parsed payload is handed unmodified to every handler for the event: [3](#0-2) 
- Handlers resolve the affected stacks from `repository.full_name`, a separate field from the one used for the signature-organization lookup: [4](#0-3) 
- `Repository.from_github_repo_name` simply splits `owner/name` from that field with no cross-check against `repository_owner`: [5](#0-4) 
- The engine's own fixtures/config demonstrate first-class support for multiple GitHub organizations/apps, each with independently-known `webhook_secret` values (`OrgOne`, `OrgTwo`): [6](#0-5) 

Binding that should hold but doesn't:
`organization authenticated by verify_signature (repository_owner) == organization of the repository actually written to (repository.full_name owner)`

Before the attack: for legitimate webhooks these two fields naturally match because GitHub itself populates `repository.owner.login` and `repository.full_name` consistently for the repository that triggered the event, and only GitHub knows the org's real webhook secret.

After the attack (an actor who is an admin/owner of OrgA, a second tenant configured on the same Shipit instance, and therefore knows OrgA's `webhook_secret` because they configured it when installing the Shipit GitHub App on OrgA): they can independently compute a valid HMAC over an arbitrary crafted JSON body using OrgA's secret, set `repository.owner.login`/`organization.login` = `OrgA` (satisfying `verify_signature`), but set `repository.full_name` = `OrgB/some-repo` (an unrelated, unaffiliated organization's tracked repository). The controller accepts the request (422 is only returned when `verified` is false or a `GithubOrganizationUnknown` is raised — note `head(422)` after a failed check does not `return`, so execution to `create` is not even reliably short-circuited, compounding the issue), and `PushHandler`/`StatusHandler`/etc. then act on OrgB's `Stack`/`Commit` records.

### Impact Explanation
This breaks a repository/organization trust boundary that Shipit explicitly relies on for multi-tenant installs (multiple GitHub Apps/orgs configured against one Shipit instance, each with its own webhook secret). An attacker who controls one tenant's webhook secret can inject arbitrary, "GitHub-signed-looking" state changes into stacks belonging to a completely different, unaffiliated organization: fabricate pushes that trigger `GithubSyncJob`/commit ingestion, forge commit statuses (`StatusHandler` creates `Commit#create_status_from_github!` records used for CI-gating deploys), forge `check_suite` results, or manipulate PR/merge-status state for review stacks — all without ever needing OrgB's actual webhook secret, a Shipit session, or an `ApiClient` token. Depending on which handler is exploited, this can affect deploy safety gates (fake "green" CI status enabling an unauthorized deploy) which maps to the required High/Critical impact classes (unauthorized deploy path, cross-repository writes).

### Likelihood Explanation
High for any Shipit deployment that hosts more than one GitHub organization/app (a documented and tested configuration shape in this engine — see the dual-app fixture). Any tenant admin who is allowed to install/administer the Shipit GitHub App for their own org automatically holds a valid credential (their org's webhook secret) sufficient to forge signed payloads targeting any other tenant's repositories, because the controller never binds the two fields together.

### Recommendation
In `WebhooksController`, after verifying the signature, re-derive and enforce that every repository/organization identifier referenced inside the payload (in particular `repository.full_name`'s owner) matches the same `repository_owner` used to select the verifying secret, rejecting (422) any payload where they diverge. Equivalently, `Handler#repository_name`/`Repository.from_github_repo_name` lookups should be constrained to repositories owned by the authenticated `repository_owner`, not resolved from a raw, independently-controlled payload field. Additionally, `verify_signature` should `return`/halt the filter chain immediately on `head(422)` rather than merely setting the response and falling through.

### Proof of Concept
1. Shipit instance is configured with two GitHub Apps/orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`), and both have Stacks tracked (`OrgA/repoA`, `OrgB/repoB`).
2. Attacker is an admin of `OrgA` and therefore knows `OrgA`'s `webhook_secret` (they configured the GitHub App webhook themselves).
3. Attacker crafts a `push` (or `status`) JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/repoB" }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and validates the signature successfully (attacker used the correct secret for OrgA). [1](#0-0) 
6. `create` dispatches the payload to `PushHandler`, which resolves `stacks` via `repository.full_name` = `"OrgB/repoB"` — an org the attacker does not control and never had to prove a signature for: [4](#0-3) 
7. `GithubSyncJob`/`Stack#sync_github` runs against `OrgB`'s stack with an attacker-chosen `expected_head_sha`, and the same technique applies to `StatusHandler` to forge commit statuses on `OrgB`'s commits — writes to a repository the forged signature never actually authorized.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
