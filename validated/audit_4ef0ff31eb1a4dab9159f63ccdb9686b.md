### Title
Webhook signature is bound to `repository.owner.login`, but Stack lookup uses the unrelated `repository.full_name` field of the same forged payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` authenticates an inbound webhook against the `webhook_secret` of the GitHub App/organization derived from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), while the handler that actually acts on the request, `Shipit::Webhooks::Handlers::Handler#repository_name`, resolves the target `Repository`/`Stack` from a completely independent field of the same attacker-controlled JSON body: `payload.dig('repository', 'full_name')`. Nothing ties these two values together, so the "organization whose secret authenticated the request" is never checked to equal "the repository whose stacks get synced/deployed."

### Finding Description
`verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to HMAC-verify the raw body against, using only the owner login pulled out of the JSON payload: [1](#0-0) [2](#0-1) 

The HMAC itself, `verify_webhook_signature`, only proves that the request was signed with *some* configured organization's secret matching `X-Hub-Signature`; it never asserts anything about which repository the payload claims to target: [3](#0-2) 

Once verification succeeds, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs the handler with the raw, attacker-controlled `params` hash: [4](#0-3) 

Every handler (e.g. `PushHandler`, driving `stack.sync_github`) resolves its target `stacks` via `Repository.from_github_repo_name(repository_name)`, where `repository_name` reads `payload.dig('repository', 'full_name')` — a different JSON key than the one used for signature scoping: [5](#0-4) [6](#0-5) [7](#0-6) 

The engine explicitly supports multiple GitHub organizations configured with independent per-organization `webhook_secret` values on a single Shipit instance: [8](#0-7) 

This is the same class of bug as the report's IAVL proof issue: the verifier binds trust to one field/path (`appHash`/store/key ≈ `repository.owner.login`), while the executed action is driven by a different, unverified field (the packet's mint target ≈ `repository.full_name`). The equality that should hold — `organization that authenticated == repository that gets written` — is never enforced.

### Impact Explanation
An attacker who controls (or can obtain a valid signature for) **any one** of the GitHub organizations configured on a shared Shipit instance (e.g. their own low-privilege org's `webhook_secret`, which they legitimately possess as an org admin) can forge a webhook whose `repository.owner.login`/`organization.login` matches their own org (so `verify_signature` passes with their own secret) but whose `repository.full_name` names a Stack belonging to a **different, higher-privilege organization** hosted on the same Shipit deployment. Handlers such as `PushHandler` will then call `stack.sync_github(expected_head_sha: ...)` for that unrelated stack, and other handlers (`status`, `check_suite`, `pull_request`, `membership`) similarly act on attacker-chosen `full_name`/team/user data despite the signature only proving authorship by an unrelated organization. This crosses the "unauthorized deploy/rollback/merge" / cross-repository-write bar: sync jobs and downstream automatic actions (auto-merge, status-driven deploy gating, check-run driven deploy pipelines) can be triggered on a target repository/stack the attacker does not control, using a signature that was never issued for that repository.

### Likelihood Explanation
Requires only that the multi-organization webhook configuration documented in `docs/setup.md` is in use (an explicitly supported, non-default-application-breaking configuration) and that the attacker controls one legitimate organization's webhook secret in that shared instance — a plausible scenario for shared/hosted Shipit deployments serving multiple teams/orgs. No GitHub App private key, `api_clients_secret`, or Shipit session is needed; only ownership of one org's own webhook secret, which is a much lower privilege than access to the target org.

### Recommendation
- Bind the verification result to the specific repository being acted upon: derive the `GitHubApp`/secret from the **same** field used by the handler layer (`repository.full_name`'s owner segment) rather than a separately-read `repository.owner.login`/`organization.login`.
- After signature verification, re-validate that the resolved `Repository.owner` matches the organization whose secret validated the signature before dispatching to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`.
- Add negative tests where `repository.owner.login` and `repository.full_name`'s owner disagree, asserting the webhook is rejected.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org example) — a Stack for `victim-org/prod-repo` exists.
2. Attacker, an admin of `attacker-org`, knows `attacker-org`'s `webhook_secret`.
3. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/prod-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org-webhook_secret, raw_body)>` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` → succeeds (correct secret/org pairing), so the request passes.
6. `PushHandler#process` resolves `Repository.from_github_repo_name('victim-org/prod-repo')` and calls `stack.sync_github(expected_head_sha: '<attacker-chosen sha>')` on the victim org's stack — despite the signature never having been produced by `victim-org`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
