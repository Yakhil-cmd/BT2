## Title
Webhook signature validated against `repository.owner.login`, but the repository actually synced is taken from the unauthenticated `repository.full_name` field, allowing cross-organization/cross-repository sync triggers - ([File: app/controllers/shipit/webhooks_controller.rb])

## Summary
This engine supports hosting multiple GitHub organizations behind one Shipit instance, each with its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` picks which organization's secret to HMAC-verify the raw POST body against by reading `repository.owner.login` (falling back to `organization.login`) out of the **unverified** JSON body, before any signature check has happened [2](#0-1) [3](#0-2) . Once the signature check passes for that org, the full raw payload is dispatched unchanged to handlers, and those handlers resolve the actual repository/stack to act on from a *different* JSON field, `repository.full_name` [4](#0-3) , e.g. in `PushHandler#process` which syncs every matching stack [5](#0-4) . Nothing enforces that `repository.owner.login` and `repository.full_name` refer to the same repository/organization — this decouples the field that is authenticated from the field that is acted on, exactly analogous to the M-5 pattern of one field being checked while a related field that drives real behavior is not.

## Finding Description
`verify_signature` derives the signing organization purely from attacker-controlled JSON, prior to verifying the signature:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

It then loads that organization's `GitHubApp` and validates `X-Hub-Signature` against the org-specific `webhook_secret` [6](#0-5) [7](#0-6) . If verification succeeds, the entire raw payload (including any other, uncorrelated `repository.full_name` value) is handed unmodified to the registered handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [8](#0-7) 

Handlers such as `PushHandler` never re-check `repository.owner.login`; they resolve the target stacks purely from `repository.full_name`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [9](#0-8) 
and then trigger `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on that repo/branch [5](#0-4) .

Binding broken (equality that should hold but doesn't): `repository.owner.login` (the field whose HMAC secret authenticated the request) == `repository.full_name`'s owner (the repository actually acted upon by the handler). GitHub itself always sends these consistently for a given real webhook delivery, but the raw JSON body is fully attacker-supplied over HTTP; nothing in `WebhooksController` or `Handler` cross-validates the two fields against each other.

Before the attacker's request: an entity holding org A's `webhook_secret` can only legitimately trigger sync/deploy-adjacent behavior for repositories under org A (as verified by `Shipit.github(organization: 'A')`).
After: by submitting a payload where `repository.owner.login = "A"` (satisfies signature check with A's secret) but `repository.full_name = "B/private-repo"` (a repository belonging to a completely different, unrelated organization/tenant configured on the same Shipit instance), the request passes `verify_signature` under org A's identity yet `PushHandler` (or other handlers relying on `repository_name`) acts on org B's stacks.

## Impact Explanation
This is a cross-repository/cross-organization write: possession of one tenant's webhook secret (org A) is escalated into the ability to force `GithubSyncJob`-driven syncing (and, depending on stack configuration such as `continuous_deployment`, downstream deploy behavior) against stacks belonging to an entirely unrelated organization (org B) that the attacker's credentials were never scoped to. This matches the "cross-repository writes / unauthorized deploy" impact bucket, because the authenticated scope (org A) and the acted-upon scope (org B) diverge.

## Likelihood Explanation
Requires the attacker to already hold a valid `webhook_secret` for at least one organization configured on the Shipit instance — this is expected to be known by whoever manages that organization's GitHub App integration, which is a much lower bar than needing org B's own secret or any Shipit session/API token. On any multi-org Shipit deployment (the officially documented `Using Multiple Github Applications` configuration) this is directly exploitable by a legitimate operator of one tenant against any other tenant on the same instance.

## Recommendation
In `WebhooksController`, after determining `repository_owner` and verifying the signature, re-derive and enforce that the repository the handlers will act on (`repository.full_name`'s owner segment) matches the same `repository_owner`/organization that was cryptographically verified, rejecting (422) any payload where these diverge. Alternatively, have `Handler#repository_name` and all subclasses consume an owner value that was itself validated against the signing organization, rather than trusting an independent field in the same unauthenticated JSON body.

## Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org config) [1](#0-0) .
2. As someone who legitimately knows `org-a`'s `webhook_secret` (e.g., an admin of org-a's own GitHub App), craft a payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": {"login": "org-a"},
    "full_name": "org-b/private-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac(org-a-webhook-secret, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner == "org-a"`, loads `Shipit.github(organization: "org-a")`, and the HMAC matches — request passes [6](#0-5) .
5. `PushHandler.call(params)` resolves `repository_name == "org-b/private-repo"` [9](#0-8)  and calls `stack.sync_github` for every matching, non-archived stack under `org-b/private-repo` [5](#0-4)  — despite the request never being signed by anything belonging to `org-b`.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
