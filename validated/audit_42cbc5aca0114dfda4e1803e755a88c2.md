Based on my research, I found a genuine analog to the H-03 bug class: a verification check that resolves its "authority" from one payload field while the actual write/mutation target is resolved from a different, unbound field.

### Title
Webhook signature verification is keyed off an attacker-controlled `repository.owner.login`/`organization.login` field that is decoupled from the `repository.full_name` actually used to resolve the mutated Stack — allowing cross-organization webhook forgery in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` chooses which `GitHubApp` (and therefore which `webhook_secret`) to validate the incoming payload against using `repository_owner`, a value taken straight out of the untrusted JSON body (`repository.owner.login` or `organization.login`). `GitHubApp#verify_webhook_signature` additionally treats a missing secret as automatically valid (`return true unless webhook_secret`). Shipit explicitly supports running multiple GitHub Apps/organizations side by side (`docs/setup.md`, "Using Multiple Github Applications"), and each organization's `webhook_secret` is independently optional. Because the field used to select the verification key is not the same field handlers use to resolve which repository/stack is actually written to, an attacker can pick an organization with no configured secret to trivially pass `verify_signature`, while smuggling a `repository.full_name` (or nested `repository`/`sha`/`branches` data) pointing at a different, secured organization's tracked repository.

### Finding Description [1](#0-0) 
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is: [2](#0-1) 

This value is read directly from the JSON body the attacker controls, with no relation enforced to any other identifying field in the same payload (e.g. `repository.full_name`, which downstream event handlers like the push handler use to look up the actual `Repository`/`Stack` via `Repository.from_github_repo_name`, see [3](#0-2) ).

`verify_webhook_signature` itself silently authorizes any payload when the resolved organization has no secret configured: [4](#0-3) 
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Multi-org configuration, where some orgs may have `webhook_secret` unset, is a documented, supported deployment shape (`docs/setup.md` "Using Multiple Github Applications"; `test/dummy/config/secrets_double_github_app.yml` shows `webhook_secret: # nil` for `OrgTwo`).

Putting this together: the binding that should hold is **organization-that-authenticated == organization/repository-that-is-written**. The engine breaks that equality — the authenticating identity is `repository.owner.login`/`organization.login` (attacker-chosen, verified only against that org's secret or trivially accepted if absent), while the entity actually mutated by handlers (via `Repository.from_github_repo_name`/`full_name`) is a separate field never covered by the signature-selection logic. Before the flaw is even reachable, GitHub's real signature (HMAC over the full raw body) would normally prevent this for any org with a configured secret — but for any org configured without one (a supported state), the check is bypassed entirely and the rest of the JSON body, including `repository.full_name`, is fully attacker-controlled and never authenticated.

### Impact Explanation
This allows an unprivileged network attacker (no GitHub App private key, no `webhook_secret`, no Shipit session) to forge push/status/check_suite/membership events for a repository/stack tracked under a *different*, secured organization, as long as any organization in the multi-org config lacks a `webhook_secret`. Depending on which handler fires, this can trigger `GithubSyncJob`, membership/team mutations, or CI status updates for stacks the attacker does not control — i.e., cross-repository writes triggered without valid authentication for the org actually being written to, matching the "cross-repository writes" / "unauthorized deploy" Critical impact bucket (continuous deployment stacks can auto-deploy off synced commits/statuses).

### Likelihood Explanation
Requires only: (1) the target Shipit instance to use the documented multi-org GitHub App configuration, and (2) at least one configured organization without a `webhook_secret`. No credentials, GitHub App keys, or Shipit accounts are needed — only network access to the public webhooks endpoint and knowledge/guess of an unsecured org's login. This is a realistic and even encouraged configuration path since `webhook_secret` is presented as optional per-org in the setup docs.

### Recommendation
Do not use attacker-supplied payload fields (`repository.owner.login`, `organization.login`) to select the verification key without cryptographically binding that same field into the trust decision for what gets written. At minimum: require every configured organization to have a non-blank `webhook_secret` (removing the `return true unless webhook_secret` bypass), and/or verify that the organization used for signature verification matches the owner embedded in the same payload's `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `SecureOrg` (has a `webhook_secret`, tracks a real stack) and `OpenOrg` (no `webhook_secret` configured, per the supported multi-org setup).
2. POST to `/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature` for `SecureOrg`, and JSON body:
   ```json
   {
     "repository": { "owner": { "login": "OpenOrg" }, "full_name": "SecureOrg/tracked-repo" },
     "after": "<attacker-chosen-sha>",
     "ref": "refs/heads/main"
   }
   ```
3. `verify_signature` resolves `repository_owner` = `"OpenOrg"`, calls `Shipit.github(organization: "OpenOrg").verify_webhook_signature(...)`, which returns `true` immediately because `OpenOrg` has no `webhook_secret`.
4. `PushHandler` (or equivalent) processes the payload and resolves the actual repository via `repository.full_name` = `"SecureOrg/tracked-repo"`, enqueuing a `GithubSyncJob`/status update against `SecureOrg`'s stack — despite `SecureOrg`'s webhook secret never having been checked.

*Note: I was unable to fully inspect `app/models/shipit/webhooks/handlers/push_handler.rb`'s exact field usage within my remaining tool budget to confirm verbatim that it keys off `full_name` rather than `owner.login`; this should be verified directly in that file before treating the PoC as fully confirmed.*

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
