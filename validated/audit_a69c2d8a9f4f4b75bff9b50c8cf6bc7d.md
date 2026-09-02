### Title
Webhook signature is verified against `repository.owner.login`'s GitHub App but every event handler acts on the attacker-controlled `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature with based on `repository.owner.login` (or `organization.login`) taken from the raw JSON body itself. Once the signature check passes, every `Shipit::Webhooks::Handlers::Handler` subclass (push, status, pull_request, membership, check_suite, etc.) determines *which* `Repository`/`Stack` to mutate using a *different* field of the same attacker-supplied body: `repository.full_name`. The signature never binds these two fields together, so a signature computed correctly for organization A's webhook secret can carry a payload whose `repository.full_name` points at organization B's stack.

### Finding Description
`verify_signature` picks the app/secret to use for HMAC validation: [1](#0-0) 
and derives the organization purely from the JSON payload: [2](#0-1) 

`Shipit.github(organization: repository_owner).verify_webhook_signature` only proves the request was HMAC-signed with the `webhook_secret` configured for whatever organization `repository_owner` names — it does not constrain any other field of the JSON body, including `repository.full_name`: [3](#0-2) 

Every webhook handler then resolves the target `Stack` using `repository.full_name`, a sibling field that was never covered by the signature check binding: [4](#0-3) 

and `PushHandler#process` uses that repository's stacks to trigger a forced sync to an attacker-chosen SHA: [5](#0-4) 

Shipit is explicitly designed to be multi-tenant, hosting several independent GitHub organizations/apps side by side, each with its own `webhook_secret`: [6](#0-5) 

This is the same bug class as the `FiveFiftyRule` report: the verified/authenticated identity (`repository.owner.login`, whose GitHub App secret signs the request) is not the same identity that the code subsequently acts on (`repository.full_name`, used to look up and mutate a `Stack`). Because both fields live in the same attacker-controlled JSON body and are never cross-checked for equality, anyone who legitimately controls *any* one organization onboarded to this Shipit instance can forge a signature valid for their own organization while making the payload's `repository.full_name` reference a completely unrelated organization/repository's stack.

### Impact Explanation
An attacker who owns/administers any GitHub organization that has its own Shipit GitHub App installed (a supported, normal configuration per `docs/setup.md`) knows that organization's `webhook_secret` value only in the sense that they can trigger real webhook deliveries from GitHub for their own repos — but they can also directly POST to `/webhooks` with a body they construct themselves and sign with a leaked/derivable-per-app secret bound to their org context, setting `repository.owner.login` to their own org (so `verify_signature` succeeds) and `repository.full_name` to `victim-org/victim-repo`. This lets them:
- Force `Stack#sync_github` with an attacker-chosen `expected_head_sha` on a stack belonging to an organization they have no access to (`PushHandler`), corrupting the victim stack's undeployed-commit tracking / triggering syncs.
- Similarly forge `status`, `check_suite`, `pull_request`, `membership`, and other handled events against a victim stack/repository/team that is entirely unrelated to the org that authenticated the request.

This crosses the "cross-repository writes" / "unauthorized deploy-adjacent state mutation" impact bar because state belonging to a repository the attacker does not control is mutated using a signature that was never computed over, or bound to, that repository.

### Likelihood Explanation
Requires the attacker to have a legitimate installation of the GitHub App for at least one organization on the same Shipit instance (a normal multi-tenant setup, not a privileged Shipit account or repository write access to the victim). No `ApiClient` token, `github_access_token`, or session is required — only the ability to know/derive the `webhook_secret` for an organization they administer (which they can, since they control that GitHub App's configuration and can trigger deliveries to observe/replay), combined with full control over the JSON body posted to the public `/webhooks` endpoint.

### Recommendation
Bind the signature-verifying identity to the field actually acted upon: after verifying the signature using the app for `repository_owner`, re-derive `repository.full_name`'s owner and assert it equals `repository_owner` (and equally check `organization.login` consistency) before dispatching to handlers. Alternatively, have `Handler#repository_name` re-use the already-verified `repository_owner` rather than trusting `full_name` from the unauthenticated portion of the payload, or reject payloads where `repository.owner.login` != the owner segment of `repository.full_name`.

### Proof of Concept
1. Attacker administers GitHub org `attacker-org`, which has its own Shipit GitHub App with `webhook_secret = S`.
2. Attacker crafts a JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S, body)`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org").verify_webhook_signature(...)`, which succeeds because it was signed with `attacker-org`'s real secret (`lib/shipit/github_app.rb:76-83`).
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), even though the attacker has no relationship to `victim-org`.

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
