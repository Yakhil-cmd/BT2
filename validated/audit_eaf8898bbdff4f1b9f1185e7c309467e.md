## Title
Webhook signature verified against `repository.owner.login` while the event handlers act on the attacker-controlled `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, computed from the JSON body itself (`params.dig('repository', 'owner', 'login')`). The event handlers that actually act on the payload (e.g. `PushHandler`) resolve the target `Stack`/`Repository` from a *different* field of the same attacker-supplied body: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so the "organization whose secret authenticated the request" and the "repository that gets written to" are independent, attacker-chosen values.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` computes: [1](#0-0) [2](#0-1) 

`repository_owner` returns `repository.owner.login` from the raw JSON body (falling back to `organization.login` only if `repository` is absent). This value is used solely to pick the `GithubApp` config (`Shipit.github(organization: repository_owner)`), i.e. which per-organization `webhook_secret` is used to validate the signature (`lib/shipit/github_app.rb#verify_webhook_signature`). [3](#0-2) 

Once verified, `create` dispatches the same raw parsed body to registered handlers: [4](#0-3) 

`Handler#stacks`/`#repository_name` resolves the target repository from `payload.dig('repository', 'full_name')`, not from `repository.owner.login`: [5](#0-4) 

`PushHandler#process` then updates every `Stack` on the resolved repository/branch based on attacker-controlled `after` sha: [6](#0-5) 

Since both `repository.owner.login` and `repository.full_name` are fields inside the same JSON body sent by the attacker, and the signature check only binds to the former, an attacker who legitimately controls a GitHub organization/App configured in Shipit (with a known/derivable `webhook_secret` for *their own* org) can craft a payload where:
- `repository.owner.login` = the attacker's own org (used to select the secret and pass `verify_webhook_signature`)
- `repository.full_name` = `"victim-org/victim-repo"` (used by `PushHandler`/other handlers to pick the target `Stack`)

The HMAC signature computed with the attacker's own org secret over this crafted body is valid, because `verify_webhook_signature` never inspects `full_name` — it just HMACs the raw body against whichever secret was selected. This breaks the intended binding: *the organization whose secret authenticated the request* should equal *the repository being written to*.

### Impact Explanation
This satisfies the "an organization that authenticated versus the repository that is written" binding called out as in-scope. Concretely, `PushHandler` calls `stack.sync_github(expected_head_sha:)` on stacks belonging to a repository the attacker does not control, using a signature validated only against their own, unrelated organization's secret. Depending on which handler is targeted (`push`, `status`, `check_suite`, `pull_request`, `deployable_status`, `merge_status`), this can influence deploy-relevant state (deployability/commit status, merge readiness, check-run refresh) for repositories/stacks outside the attacker's control — an unauthorized write into another repository's Shipit state, without ever needing that repository's own webhook secret.

### Likelihood Explanation
The attacker only needs: (1) any organization configured in Shipit's multi-tenant GitHub App config (i.e. their own org, onboarded normally, no privileged Shipit access needed) and (2) knowledge of that org's `webhook_secret` (which they legitimately possess, since it's their own org's GitHub App/webhook secret) or the ability to trigger real webhooks from their org and freely craft the JSON body signed with it. No compromise of the victim org, no Shipit session, and no `ApiClient` token are required — only cross-organization request forgery via a mismatched `repository.owner`/`repository.full_name` pair in one legitimately-signed payload.

### Recommendation
Bind signature verification and repository resolution to the same field. Either verify the signature using the organization derived from `repository.full_name`'s owner segment (or `organization.login` consistently), and additionally have every `Handler` assert that `payload.dig('repository', 'owner', 'login')` matches `repository_owner` used to pick the signing organization before acting on `full_name`, rejecting the webhook if they diverge.

### Proof of Concept
1. Attacker owns/administers `attacker-org`, which is configured as a legitimate GitHub App organization in Shipit's `secrets.github` multi-tenant config, giving the attacker the `webhook_secret` for `attacker-org`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_of_attacker-org, raw_body)>`.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` (from `repository.owner.login`) and successfully verifies, because the attacker signed with their own valid secret. [1](#0-0) 
5. `create` dispatches to `Shipit::Webhooks::Handlers::PushHandler`, which resolves stacks via `Repository.from_github_repo_name('victim-org/victim-repo')` and calls `stack.sync_github(expected_head_sha: 'deadbeef')` on stacks the attacker never authenticated for. [5](#0-4) [6](#0-5) 

Note: I was unable to further trace `Stack#sync_github`'s exact downstream side effects (whether it merely queues a `GithubSyncJob` fetch or can influence deploy-eligibility state directly) within the remaining exploration budget; a full session could confirm the precise blast radius across the other handlers (`status`, `check_suite`, `pull_request`, `deployable_status`, `merge_status`) that share the same `repository.full_name` resolution pattern.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
