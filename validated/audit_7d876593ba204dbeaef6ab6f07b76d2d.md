This confirms the vulnerability: `Repository#from_github_repo_name` looks up by `owner`/`name` split from `github_repo_name` = `payload.dig('repository', 'full_name')`, an entirely separate JSON field from `repository.owner.login` used for signature-org selection, and both live in the same unverified request body prior to signature verification. [1](#0-0) 

### Title
Webhook signature is verified against the organization named in `repository.owner.login`, while event handlers act on the independent, unverified `repository.full_name` field, allowing an organization with a valid `webhook_secret` to write to another organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` used to verify the HMAC by reading `repository.owner.login` (or `organization.login`) straight out of the still-unverified JSON body, via `Shipit.github(organization: repository_owner)` and `GithubApp#verify_webhook_signature`. [2](#0-1)  Once the signature check passes, `create` re-parses the same raw body and dispatches it to handlers (`PushHandler`, `StatusHandler`, etc.) that resolve the target `Stack`/`Repository` from a *different* field, `repository.full_name`, via `Handler#repository_name`/`#stacks` and `Repository.from_github_repo_name`. [3](#0-2) [4](#0-3)  Because `repository.owner.login` (used for auth) and `repository.full_name` (used to pick the write target) are two independent, attacker-controlled fields in the same signed byte string, nothing binds them together: the HMAC only proves the bytes weren't tampered with by a third party, it does not prove the two fields are self-consistent.

### Finding Description
The engine supports multiple GitHub organizations, each configured with its own `webhook_secret` in `secrets.yml` (see `config/secrets.development.shopify.yml`). [5](#0-4)  Any principal who legitimately administers one organization's GitHub App (e.g., a team that self-registered its own org/app on a shared Shipit instance) knows that organization's `webhook_secret`. Using that secret, they can craft an arbitrary POST to `/webhooks` where:
- `repository.owner.login` = their own organization (`orgA`) — satisfies `verify_signature`'s `Shipit.github(organization: repository_owner)` lookup and HMAC check.
- `repository.full_name` = `orgB/some-repo` (a repository belonging to a *different* organization they don't control) — this is the field `Handler#repository_name` and `Repository.from_github_repo_name` use to locate the `Stack` that the handler acts on.

Since `verify_signature` never checks that `repository.owner.login` and `repository.full_name`'s owner segment agree, and the handler logic never re-validates that the payload's claimed owner matches the actual target repository's owner, the signature-authenticated organization (`orgA`) and the repository actually written to (`orgB/...`) diverge. Concretely, a forged `push` event with `repository.full_name = "orgB/some-repo"` and a valid `after` SHA drives `PushHandler#process` to call `stack.sync_github(expected_head_sha: params.after)` on `orgB`'s stack, which enqueues `GithubSyncJob` and ultimately syncs/deploys commits based on attacker-supplied data for a repository the attacker does not own. [6](#0-5) 

The equality that should hold but is broken:
`organization authenticated by verify_signature (repository.owner.login)` == `organization implicitly authorized by the repository the handler writes to (repository.full_name)`.

### Impact Explanation
This crosses the "cross-repository writes" boundary explicitly called out as Critical impact: an org that only possesses credentials (webhook_secret) for its own tenant can trigger `GithubSyncJob` and downstream deploy-spec caching/sync actions on another organization's `Stack`, without ever needing that organization's webhook secret, GitHub App credentials, or Shipit session. Depending on which handler is targeted (`push`, `status`, `check_suite`, `pull_request`, `membership`), this can inject fabricated commit statuses, alter merge/deploy eligibility signals, or otherwise pollute state for a stack outside the attacker's control.

### Likelihood Explanation
This is exploitable by any unprivileged party that legitimately controls one org's GitHub App/webhook configuration on a shared/multi-tenant Shipit deployment — a realistic scenario since Shipit is designed to serve many organizations from a single instance (`Shipit.github(organization: ...)` keys off arbitrary org names in `secrets.yml`). No knowledge of the victim organization's secret, no repository write access to the victim repo, and no Shipit account are required — only a raw HTTP POST with a correctly-computed HMAC using the attacker's own known secret.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), assert that the repository named in the payload actually belongs to the organization whose secret validated the signature — e.g., compare `repository_owner` against the owner segment of `repository.full_name` (and `organization.login` where present) and reject (422) on mismatch before dispatching to any handler.

### Proof of Concept
1. Attacker legitimately administers `orgA`'s GitHub App on a shared Shipit instance and knows `orgA`'s `webhook_secret`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(orgA_webhook_secret, body)` and sets `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"orgA"`, fetches `orgA`'s `GithubApp`, and the HMAC validates successfully. [1](#0-0) 
5. `create` dispatches the same body to `PushHandler`, which resolves `repository_name = "orgB/victim-repo"` and locates `orgB`'s `Stack` via `Repository.from_github_repo_name`, then calls `stack.sync_github(expected_head_sha: ...)` — a write against `orgB`'s stack the attacker never authenticated for. [6](#0-5)

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

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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
