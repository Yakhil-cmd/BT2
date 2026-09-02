### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the event is applied to whatever repository is named in `repository.full_name` — allowing cross-organization webhook forgery in multi-tenant deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate an incoming webhook against using `repository_owner`, a value read straight out of the *unverified* JSON body. The event is then dispatched and, deep inside every handler, the repository/stack that is actually acted upon is resolved from a *different* field of the same unverified body: `repository.full_name`. Nothing ties these two fields together, so the field that is authenticated (`repository.owner.login`/`organization.login`) is not the field that is acted on (`repository.full_name`).

### Finding Description
`verify_signature` picks the GitHub App config purely from the payload: [1](#0-0) 

`repository_owner` is derived from the raw, not-yet-verified request body: [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GitHubApp` instance configured for that organization, and `verify_webhook_signature` HMACs the raw body against that organization's own `webhook_secret`: [3](#0-2) 

Once the signature is accepted, `WebhooksController#create` hands the same unverified JSON to the event handlers: [4](#0-3) 

Every handler (`PushHandler`, `CheckSuiteHandler`, `StatusHandler`, the `pull_request` handlers, etc.) resolves the target repository/stack via `Handler#repository_name`, which reads `repository.full_name` — a completely independent field from the one used for signature selection: [5](#0-4) 

Shipit explicitly supports hosting multiple GitHub organizations from a single instance, each with its own `webhook_secret`, keyed by organization name in `config/secrets.yml`: [6](#0-5) 

Because the field used to pick the verification secret (`repository.owner.login` / `organization.login`) is never checked for equality against the field used to pick the repository that is acted on (`repository.full_name`), an attacker who legitimately controls a GitHub App/organization "A" hosted on the same Shipit instance (and therefore knows organization A's `webhook_secret`, since they configured it themselves) can forge a request where:
- `repository.owner.login` = `"A"` (so `verify_webhook_signature` validates using secret A, which the attacker correctly computes), while
- `repository.full_name` = `"B/victim-repo"` (a different, victim organization/repository hosted on the same shared instance).

The equality that should hold — `organization authenticated == organization whose repository is written` — is broken.

### Impact Explanation
This lets a party who is only authorized for organization A's webhook credentials inject arbitrary, validly-"signed" webhook events (`push`, `status`, `check_suite`, `pull_request`) that Shipit will process as if they originated from organization B. Depending on the handler this can:
- Force `PushHandler` to trigger `stack.sync_github` for organization B's stacks on attacker-chosen refs/SHAs.
- Force `StatusHandler`/`CheckSuiteHandler` to write forged commit statuses/check results for organization B's commits, which the merge queue (`merge_status`) consults when deciding whether a PR is mergeable — enabling an unauthorized merge of organization B's code by faking a passing status.
- Manipulate `pull_request` handlers (label/close/reopen) against organization B's stacks.

This maps to the "organization authenticated vs. repository written" binding called out in scope, and its worst-case consequence (forged status causing an unauthorized merge) falls under the in-scope Critical/High impact of "an unauthorized deploy, rollback or merge." It only applies to Shipit installations configured with multiple GitHub organizations sharing one Shipit instance, and requires the attacker to control (or know) one tenant organization's own `webhook_secret` — a credential they legitimately possess for their own org, but not authorization over the victim org's repositories.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (explicitly documented/supported), and (2) attacker control of one tenant's webhook secret (which any org admin configuring their own GitHub App has). Given that, forging the request is trivial — compute an HMAC-SHA1 over a crafted JSON body with the victim's `repository.full_name` and the attacker's own `repository.owner.login`, and POST it to `/webhooks`. No session, no GitHub token, and no privileged Shipit account is needed.

### Recommendation
After identifying `repository_owner` for secret selection, cross-check that the organization encoded in `repository.full_name` (and/or `organization.login`) matches `repository_owner` before dispatching to handlers, and reject (422) on mismatch. Alternatively, verify the signature using a per-repository/stack secret resolved from `repository.full_name` itself rather than a separate owner field, so the value used to select the verification key is the same value later trusted to identify the target repository.

### Proof of Concept
1. Shipit is configured with two organizations, `A` and `B`, each with its own `github.webhook_secret` (per `docs/setup.md` multi-org example).
2. Attacker, who administers org `A`'s GitHub App, knows secret `S_A`.
3. Attacker crafts a `push` webhook body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha that exists on B's repo>",
  "repository": {
    "full_name": "B/victim-repo",
    "owner": { "login": "A" }
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "A")` (from `repository.owner.login`), verifies successfully against `S_A`. [1](#0-0) 
6. `PushHandler#process` resolves `Repository.from_github_repo_name("B/victim-repo")` from `repository.full_name` and runs `stack.sync_github(expected_head_sha: params.after)` against organization B's stack, despite the request never being authenticated with any secret belonging to organization B. [5](#0-4) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
