### Title
Cross-organization stack write via mismatch between the organization that verifies the webhook signature and the repository the handler acts on - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GithubApp`/`webhook_secret` to authenticate a webhook delivery using `repository.owner.login` (or `organization.login`) pulled straight out of the untrusted JSON body, while the event handlers (`Handler#stacks`/`Handler#repository_name`, e.g. `PushHandler`) act on `repository.full_name` from that same body. Nothing enforces that these two fields describe the same repository/organization. In a multi-tenant Shipit deployment (Shipit explicitly supports configuring several independent GitHub organizations, see `config/secrets.development.shopify.yml`), a party who legitimately controls the `webhook_secret` for **one** configured organization can forge a signed payload whose `repository.owner.login` matches their own organization (so the signature check passes) but whose `repository.full_name` names a stack belonging to a **different** configured organization, causing Shipit to sync/deploy state for a repository the sender was never authorized to touch.

### Finding Description
`WebhooksController#verify_signature` computes the GitHub app/secret to validate against solely from a value taken from the still-unverified request body: [1](#0-0) 

and [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login')`. `Shipit.github(organization: repository_owner)` (see `GithubOrganizationUnknown` handling and per-organization config in `lib/shipit.rb`, lines 62-63) looks up the `webhook_secret` configured for *that specific organization* and uses it to validate `X-Hub-Signature` against the raw body.

Once the signature is accepted, `create` dispatches to handlers with the same JSON body: [3](#0-2) 

The handlers, however, resolve the target `Stack`/`Repository` using a **different** field of the same payload, `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

`PushHandler`, for instance, uses `stacks` (from `Handler`) keyed off `repository_name` = `repository.full_name`, then triggers `stack.sync_github`: [5](#0-4) 

`Repository.from_github_repo_name` splits `full_name` on `/` and does an independent `owner`/`name` lookup: [6](#0-5) 

**The broken binding:** the code implicitly assumes `organization that signed/authenticated the webhook == organization of the repository being written to`, but this equality is never checked. The signature only proves "this body was produced with organization A's `webhook_secret`"; it says nothing about which repository the handlers should act on, because the handlers read the target repository from a field (`full_name`) that is not cross-checked against the field used for authentication (`owner.login`).

Legitimate GitHub-originated deliveries keep these two fields consistent because GitHub itself fills in the payload. But an attacker does not need to go through GitHub: the endpoint is a plain HTTP POST (`config/routes.rb`: `resources :webhooks, only: :create`) that accepts any JSON body with a valid `X-Hub-Signature` for *any one* of the organizations configured in this Shipit instance. If the operator hosts multiple, independently-trusted GitHub organizations behind one Shipit instance (a supported, documented configuration — see `config/secrets.development.shopify.yml` showing `somegithuborg`/`someothergithuborg`), the admin/owner of the lower-trust organization "A" (who legitimately possesses/knows A's `webhook_secret` because they created A's GitHub App) can craft:
```json
{
  "repository": {"owner": {"login": "A"}, "full_name": "B/victim-repo"},
  "ref": "refs/heads/main",
  "after": "<attacker-controlled sha>"
}
```
sign it with A's `webhook_secret`, and POST it to `/webhooks`. `verify_signature` selects A's app/secret (because `repository.owner.login == "A"`), the signature checks out, and `PushHandler` then calls `stack.sync_github(expected_head_sha: ...)` on organization B's stack — an org the sender never authenticated as.

### Impact Explanation
This breaks a deployment-trust binding explicitly called out as in-scope: "an organization that authenticated versus the repository that is written." The consequence is a cross-organization/cross-repository write: an attacker who is only trusted for organization A's webhook traffic can force Shipit to process a forged push/status/check_suite/pull_request event as if it originated from organization B, driving `stack.sync_github`, commit status creation, or check-run refreshes against B's stacks. Depending on which event/handler is abused (e.g. forcing sync of arbitrary commit SHAs into B's deploy history, or manipulating merge/CI status used to gate deploys) this can influence or trigger unauthorized deploys of organization B's stacks — matching the "cross-repository writes / unauthorized deploy" Critical-impact category.

### Likelihood Explanation
Medium: it requires the operator to run Shipit in a genuine multi-organization configuration and for the attacker to be a legitimate, trusted party for *at least one* of the configured organizations (i.e., they can obtain/rotate that org's GitHub App `webhook_secret`, which is normal self-service for a GitHub App admin of their own org). No GitHub App private key, `ApiClient` token, session, or `api_clients_secret` is needed — only knowledge of one tenant's webhook secret, which is by design available to that tenant.

### Recommendation
1. After computing `repository_owner` and verifying the signature, re-derive the acting organization from the same trusted field and require it to equal the organization embedded in `repository.full_name` (and in `organization.login` for org-level events) before dispatching to handlers; reject (422) on mismatch.
2. Alternatively, scope handler-side repository/stack lookups to the already-authenticated organization instead of re-parsing `full_name` independently, e.g. pass the verified organization into `Handler` and assert `repository.owner == verified_organization` in `Handler#stacks`/`Handler#repository_name`.
3. Add a regression test asserting a payload signed by organization A's secret but referencing organization B's `repository.full_name` is rejected.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `orgA` and `orgB`, each with its own `webhook_secret` (as supported by `config/secrets.development.shopify.yml`).
2. As the (legitimate) GitHub App admin of `orgA`, obtain `orgA`'s `webhook_secret`.
3. Craft a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha present in orgB/victim-repo>",
  "repository": {"owner": {"login": "orgA"}, "full_name": "orgB/victim-repo"}
}
```
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>`.
5. `POST /webhooks` with header `X-Github-Event: push` and the above body/signature.
6. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA")`, validates the signature successfully with `orgA`'s secret, per `app/controllers/shipit/webhooks_controller.rb:24-30`.
7. `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) resolves stacks via `Repository.from_github_repo_name("orgB/victim-repo")` (`app/models/shipit/repository.rb:53-56`) and calls `stack.sync_github(expected_head_sha: "<attacker chosen sha>")` on `orgB`'s stack, even though the request was never authenticated for `orgB`.

Note: I could not find any additional cross-check elsewhere in the request path (e.g., in `GithubSyncJob` or `Stack#sync_github`) that re-validates the organization of the target repository against the organization used to verify the signature; if such a check exists outside the indexed portions of the codebase, it was not found in this pass and I'd recommend explicitly verifying with a full Devin session against the live repository before treating this as fully unmitigated.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
