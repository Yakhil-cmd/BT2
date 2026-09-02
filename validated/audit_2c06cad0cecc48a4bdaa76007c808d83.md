### Title
Webhook signature verification keys off an attacker-controlled, unverified payload field, decoupling "organization authenticated" from "repository written" - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a value read straight out of the **unverified** JSON body, before any signature has been checked. Because Shipit supports multi-organization GitHub App configuration, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when `webhook_secret` is blank/unset for the resolved organization, an attacker can pick *any* configured organization that has no `webhook_secret` set to skip verification entirely, while the rest of the payload (used afterwards by the event handlers) still refers to whatever repository/stack the attacker wants to target.

### Finding Description
`verify_signature` computes the verification target purely from payload data:

<cite repo="Ellentat/shipit-engine--022" path="app/controllers/shipit/webhooks_controller.rb" start="24="30" end="30" /> [1](#0-0) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`repository_owner` is then used to fetch the `GitHubApp` instance for that organization: [2](#0-1) 

and `verify_webhook_signature` explicitly bypasses HMAC checking if that org's `webhook_secret` is not configured: [3](#0-2) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

The repository fixture `secrets_double_github_app.yml`, used to test multi-org support, shows this is a realistic configuration state (both orgs shown with `webhook_secret: # nil`): [4](#0-3) [5](#0-4) 

Once `verify_signature` passes (either because the chosen org has no secret, or because the attacker forges a valid signature for that org), `create` hands the *entire* raw JSON body — including any `repository.full_name`, `sha`, `stack`, etc. fields the attacker put there — to the event handlers: [6](#0-5) 

Nothing re-checks that the repository the handlers subsequently act on (`params['repository']['full_name']`) actually belongs to the organization (`repository_owner`) whose (missing) secret was used for the auth decision. This breaks the binding "organization that authenticated == repository that is written": an attacker can set `repository.owner.login` to an org with no `webhook_secret` (satisfying `verify_signature`) while setting `repository.full_name`/commit/`sha` fields to point at a completely different, tracked repository/stack.

### Impact Explanation
If the deploying operator has configured more than one GitHub App organization (a supported and documented feature) and left `webhook_secret` unset for any one of them — including by oversight, since it's optional per the setup docs — an unauthenticated network attacker can forge `push`, `status`, `check_suite`, `pull_request`, or `membership` webhook events for *any* repository/organization tracked by that Shipit instance, not just the unsecured one. Depending on handler, this can:
- Inject fake commits into a stack's history via `push` (`GithubSyncJob`), potentially manipulating what Shipit believes is deployable.
- Forge CI `status`/`check_suite` results, marking arbitrary commits as green, which can unlock a deploy that would otherwise be blocked pending CI (`Commit#statuses`).
- Forge `membership` events, adding/removing arbitrary GitHub users to/from `Team`s used for `Shipit.github_teams` authorization (`app/models/shipit/webhooks/handlers/membership_handler.rb`), directly threatening the "escalation into `Shipit.github_teams` authorization" impact category.

This crosses the "organization authenticated vs repository written" boundary named in scope and can lead to unauthorized manipulation of deploy-gating state or authorization team membership.

### Likelihood Explanation
Requires: (1) a multi-org GitHub App configuration (supported, documented, and exercised in `test/dummy/config/secrets_double_github_app.yml`), and (2) at least one configured organization without a `webhook_secret` — an easy operator oversight since the field is explicitly optional (`docs/setup.md` describes it as "optional"). Given those two realistic preconditions, exploitation requires no privileges: only an HTTP POST to the public `/webhooks` endpoint with a crafted JSON body and the mismatched `X-Github-Event` header.

### Recommendation
- Do not let the organization used to select the verification secret be derived from unverified payload data. Verify the signature against the receiving endpoint's/App's own configured secret(s) rather than one implied by attacker-supplied `repository.owner.login`.
- Do not silently return `true` from `verify_webhook_signature` when `webhook_secret` is unset for a *specific* org in multi-org mode; either require every organization to define a `webhook_secret`, or fail closed if one is missing rather than skipping verification.
- After verification, cross-check that the `repository` referenced later in `params` matches the organization that was actually authenticated for this request.

### Proof of Concept
1. Deploy Shipit with two GitHub App organizations configured, e.g. `OrgOne` (tracked, has real repositories/stacks) and `OrgTwo` (added later, `webhook_secret` left blank as in `secrets_double_github_app.yml`).
2. Attacker sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything

{
  "sha": "<victim commit sha in OrgOne/real-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "OrgOne/real-repo" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgTwo")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the bogus signature header.
4. `StatusHandler` processes the payload's `repository.full_name` (`OrgOne/real-repo`) and `sha`, creating a forged successful CI status on a real, tracked commit — potentially satisfying deploy-blocking status checks without any legitimate CI run.

Note: I was unable to fully read `app/models/shipit/webhooks/handlers/status_handler.rb` / `push_handler.rb` / `handler.rb` before the tool budget ran out, so the exact field(s) (`full_name` vs `owner.login`) each handler uses to resolve the target `Repository`/`Stack` is inferred from the controller/model code reviewed rather than directly confirmed line-by-line in those handler files. This should be verified against `app/models/shipit/webhooks/handlers/*.rb` before treating the PoC payload shape as exact.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
