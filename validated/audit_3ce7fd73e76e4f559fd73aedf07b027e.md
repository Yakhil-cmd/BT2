### Title
Webhook signature verified against `repository.owner.login`/`organization.login` while handlers act on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to check the HMAC against using `repository_owner`, derived from `params.dig('repository','owner','login')` (or `params.dig('organization','login')` as fallback). Once the signature passes, `create` dispatches the *entire* raw JSON payload to `Shipit::Webhooks.for_event(event)` handlers, which independently resolve the target `Repository`/`Stack` using `payload.dig('repository', 'full_name')` [1](#0-0) . These are two different fields read from the same attacker-controlled JSON body, and nothing ties them together.

### Finding Description
The signature check is: [2](#0-1) 
It looks up the GitHub App config for `repository_owner`: [3](#0-2) 

Once verified, `create` hands the full parsed body to every handler for the event: [4](#0-3) 

Handlers such as `PushHandler` resolve which `Stack`/`Repository` to act on from a *different* JSON field, `repository.full_name`, not `repository.owner.login`: [5](#0-4) [6](#0-5) 

The binding that should hold is: `organization authenticated (repository.owner.login used to pick webhook_secret) == organization of the repository actually written to (repository.full_name used by handlers)`. The signature only proves the payload was HMAC-signed with the secret configured for whatever organization the `repository.owner.login`/`organization.login` field claims — it says nothing about which repository `repository.full_name` refers to. Anyone who possesses the webhook secret for organization A (e.g., because they legitimately set up/administer a webhook on a repository in org A that is connected to this Shipit instance) can compute a valid `X-Hub-Signature` over an arbitrary JSON body. They can set `repository.owner.login` (or `organization.login`) to `"org-A"` so `verify_signature` picks org A's secret and passes, while setting `repository.full_name` to `"org-B/some-repo"` — a stack belonging to a completely different, unrelated organization/repository configured in the same Shipit deployment. `PushHandler#process` (and other handlers keyed off `repository_name`) will then look up and act on org B's `Stack`, e.g., invoking `stack.sync_github(expected_head_sha: params.after)`, `membership_handler`, `check_suite_handler`, or PR handlers for a repository the attacker never had any relationship with.

This is a real analog to the audit's `NoYield.emergencyWithdraw` finding class only in that both bugs stem from one identity/field being checked while a *different* field is used for the actual privileged action — here it is precisely the "organization that authenticated versus the repository that is written" binding named in scope.

### Impact Explanation
This crosses the "cross-repository writes" impact bucket: a party who only controls webhook credentials for one organization/repository connected to a multi-tenant Shipit instance can forge events that are dispatched against an unrelated organization's `Stack`/`Repository`, triggering handler side effects (sync jobs, team/membership creation, check-suite refresh, PR/label bookkeeping) scoped to a repository they do not own. Because `Shipit::Webhooks.for_event` fans the same payload out to every handler for the event and none of them re-validate that `repository.full_name`'s owner matches the organization whose secret produced the signature, the trust boundary between organizations configured on the same Shipit instance is not enforced.

### Likelihood Explanation
Exploitability requires the attacker to know a valid `webhook_secret` for at least one organization/app configuration wired into this Shipit instance — this is the same kind of secret that is explicitly called out as out-of-scope input (`webhook_secret`) in the general case, but here it is being used as the *pivot* to attack a *different* organization's data, not to attack the org that owns the secret. In a Shipit deployment that legitimately serves multiple organizations (which the multi-organization `Shipit.github(organization:)` lookup, `GithubOrganizationUnknown` fallback logic, and repository_owner fallback all imply is a supported topology), any org onboarded to the platform effectively becomes a way to forge writes into every other org's stacks, since the signature check and the routing key are decoupled. This is a design-level authorization gap rather than a rare edge case.

### Recommendation
Bind the signature-verifying identity to the identity actually acted upon: after verifying the signature with the secret selected for `repository_owner`, re-derive the same owner from `repository.full_name` (or `organization.login`) used by `Shipit::Webhooks::Handlers::Handler#repository_name` and reject the request (e.g., `head(422)`) if they disagree. Alternatively, have handlers resolve the target `Repository` using the same owner value that was used to select the webhook secret, so a single JSON payload cannot claim one organization for authentication and a different one for the write target.

### Proof of Concept
1. Configure Shipit with two organizations, `org-A` and `org-B`, each with its own `webhook_secret` (a supported, documented multi-org topology per `Shipit.github(organization:)`).
2. Attacker legitimately possesses/knows `org-A`'s `webhook_secret` (e.g., they set up the webhook on a repo they administer in org A).
3. Attacker crafts a JSON body for a `push` event:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "org-A" }, "full_name": "org-B/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(webhook_secret_orgA, body)` and POSTs it to `/github/webhooks`.
5. `verify_signature` calls `Shipit.github(organization: "org-A")` (from `repository.owner.login`) and the HMAC matches → request accepted.
6. `create` dispatches the body to `PushHandler`, which computes `repository_name` from `repository.full_name` = `"org-B/victim-repo"`, resolves the actual `Stack` belonging to org B, and calls `stack.sync_github(expected_head_sha: params.after)` — an action against an organization the attacker never authenticated for. [7](#0-6) [5](#0-4)

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
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
```
