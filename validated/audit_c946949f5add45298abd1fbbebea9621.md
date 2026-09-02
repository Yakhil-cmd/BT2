## Title
Webhook signature is verified against the organization named in `repository.owner.login`, while the sync/handler logic acts on the unrelated `repository.full_name` field of the same payload — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate the inbound webhook against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted, attacker-supplied JSON body. Once the HMAC check passes, every downstream `Handler` (e.g. `PushHandler`) instead resolves the target `Stack`/`Repository` using a *different* field from the same body, `repository.full_name`, via `Handler#repository_name`/`Handler#stacks`. Nothing ties the "organization whose secret validated this request" to the "repository the request is allowed to act on." [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
This is a direct analog of the reentrancy report's core bug class: a value that is *acted on* is not the same value that was *verified*. In the smart-contract report, `LoanManager.claim` re-reads loan state that was already mutated mid-call, so the effect diverges from what was authorized. Here, the divergence is even more direct and doesn't require any re-entrant call — it's baked into a single request:

- `verify_signature` picks the `GitHubApp` (and its `webhook_secret`) using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [4](#0-3) 
- The HMAC (`verify_webhook_signature`) only proves that *someone who knows OrgX's webhook_secret* crafted the raw body — it says nothing about which repository the payload's other fields describe. [5](#0-4) 
- Every `Handler` subclass then determines the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')`, with no cross-check against `repository.owner.login` or against which `GitHubApp`/org validated the signature. [2](#0-1) 

Shipit explicitly supports hosting multiple, independently configured GitHub Apps/organizations from one instance (`config/secrets.yml` `github.<org>.webhook_secret`), each with its own secret. [6](#0-5) 

Binding that should hold, expressed as an equality:
`organization whose webhook_secret validated the request == organization that owns the repository the handler acts on`

Before the attacker's request: for legitimate GitHub-originated webhooks, `repository.owner.login` and `repository.full_name`'s owner segment are always the same, so the equality holds implicitly (not because it's checked, but because GitHub itself only ever sends a consistent payload).

After the attacker's request: an operator/user who legitimately controls a GitHub App installation for `OrgX` (and therefore genuinely knows `OrgX`'s real `webhook_secret` — this is not a Shipit secret, it's issued by GitHub App settings which any user administering an org's GitHub App can read) can compute a valid HMAC over a forged JSON body where `repository.owner.login = "OrgX"` (so `verify_signature` selects and validates against `OrgX`'s secret and passes) but `repository.full_name = "OrgY/victim-repo"` — a repository/stack registered under a completely unrelated organization `OrgY` hosted on the same Shipit instance. `PushHandler#process`/`Handler#stacks` will happily resolve `OrgY/victim-repo`'s `Stack`(s) and invoke `stack.sync_github(expected_head_sha: params.after)`, or for the `PullRequest` handlers, mutate PR/label/review state on `OrgY`'s stacks. [7](#0-6) 

### Impact Explanation
This breaks the deployment-trust binding between "the organization/app installation whose credentials authenticated the request" and "the repository whose state gets written," matching the rules' definition of an in-scope crossing. The most severe realistic consequence is triggering `sync_github` (a `GithubSyncJob`) against a victim stack the attacker's organization was never installed on or granted access to — `sync_github` re-syncs commits/statuses and, on stacks with continuous delivery/continuous deployment enabled, can advance/trigger deploy state for commits the attacker did not push and has no write access to. That is an unauthorized cross-repository write/trigger of deploy machinery from an org boundary that should not be able to touch it, which lands in the report's "cross-repository writes" / "unauthorized deploy" High/Critical bucket.

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured with more than one GitHub organization (documented, supported configuration — `docs/setup.md` "Using Multiple Github Applications"), and (2) the attacker to control/administer a real GitHub App installation for at least one of those configured orgs (obtaining its genuine `webhook_secret`), which is plausible in shared/multi-tenant Shipit deployments where org admin trust is not uniform. No Shipit session, `ApiClient` token, or private key is needed — only the legitimately-issued webhook secret for the attacker's own org, which the controller never scopes to the repositories it's allowed to describe.

### Recommendation
After signature verification selects `repository_owner` and its `GitHubApp`, `WebhooksController`/`Handler` should verify that `payload.dig('repository', 'full_name')`'s owner segment matches the `repository_owner`/organization whose secret validated the signature, rejecting (422) on mismatch, before any handler resolves or mutates a `Stack`.

### Proof of Concept
1. Deploy Shipit with two orgs configured, `OrgX` and `OrgY`, each with their own GitHub App and `webhook_secret` (per `docs/setup.md`'s multi-org example).
2. As the administrator of `OrgX`'s real GitHub App (attacker), craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha already present on victim repo>",
     "repository": { "owner": { "login": "OrgX" }, "full_name": "OrgY/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgX_webhook_secret, body)>` using the attacker's genuinely-known `OrgX` secret.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `Shipit.github(organization: "OrgX")` and the HMAC checks out, so the request passes. [8](#0-7) 
5. `PushHandler.call(params)` runs and resolves `Repository.from_github_repo_name("OrgY/victim-repo")`, triggering `stack.sync_github(expected_head_sha: ...)` on a stack the attacker's `OrgX` credentials have no legitimate relationship to. [3](#0-2)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
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
