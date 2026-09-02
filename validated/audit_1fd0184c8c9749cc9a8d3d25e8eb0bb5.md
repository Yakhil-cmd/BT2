### Title
Webhook signature verification selects the signing organization from `repository.owner.login`, but event handlers act on the independent `repository.full_name` field, allowing an attacker who holds one organization's `webhook_secret` to forge events for a different organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` picks *which* GitHub App / `webhook_secret` to validate the HMAC signature with based on `repository.owner.login` (or `organization.login`) taken from the still-unauthenticated JSON body. [1](#0-0) [2](#0-1)  Once the signature is accepted, `Shipit::Webhooks::Handlers::Handler` and its subclasses (`PushHandler`, `StatusHandler`, `PullRequest::ClosedHandler`, etc.) resolve the actual `Repository`/`Stack` to mutate using a *different* field in the same body, `repository.full_name`. [3](#0-2)  Nothing in the controller or the handlers checks that `repository.owner.login` and the owner encoded in `repository.full_name` refer to the same organization.

### Finding Description
Shipit supports hosting multiple GitHub organizations from one instance, each with its own `webhook_secret` configured under `github: <org>: webhook_secret`. [4](#0-3)  The binding the security model relies on is:

`organization whose secret authenticated the request == organization that owns the repository being written to`

`verify_signature` looks up the app/secret with `Shipit.github(organization: repository_owner)` where `repository_owner` is read directly, unauthenticated, from the JSON payload (`repository.owner.login`, falling back to `organization.login`): [5](#0-4) [2](#0-1) 

After the HMAC check passes, `create` simply hands the same raw params to the registered handler for the event: [6](#0-5) 

The handler base class, and every subclass that resolves a repository, use a completely separate field, `repository.full_name`, to look up the target `Repository`/stacks: [3](#0-2) [7](#0-6) [8](#0-7) 

Because `verify_signature` never confirms that `repository.owner.login` is consistent with the owner segment of `repository.full_name`, an attacker who legitimately controls (or has been granted) the `webhook_secret` for organization A can freely construct the rest of the JSON body — including setting `repository.full_name` to `"orgB/some-repo"`, a repository belonging to an entirely different, unrelated organization B also hosted on the same Shipit instance. The signature will be computed and verified against org A's secret (which the attacker legitimately possesses), so `verify_signature` passes, yet the handler acts on org B's stack.

This exactly mirrors the reported bug class: a value used to satisfy an authorization/verification check (`repository.owner.login`, which selects the trust boundary/secret) is never bound to the value that is actually acted upon (`repository.full_name`, which selects the mutated resource) — the same class of "field acted on but never covered by the verified signature" flaw the external report describes for `Berabot`, where the fee/slippage logic used a different value than the one meant to be protected.

### Impact Explanation
Depending on the event type, this crossing of the organization-authentication boundary into another organization's repository allows:
- `StatusHandler`: injecting arbitrary/fake commit statuses on commits belonging to a repository/organization the attacker does not control, which can influence deploy safety gating decisions. [9](#0-8) 
- `PushHandler`: forcing a `GithubSyncJob`/`sync_github` on a stack belonging to a different organization's repository, causing unsolicited resynchronization. [7](#0-6) 
- `PullRequest::ClosedHandler`: archiving review stacks belonging to a different organization's repository. [10](#0-9) 

This is a cross-repository/cross-organization write triggered purely by controlling one organization's webhook secret, which meets the "cross-repository writes" Critical-impact bar defined in scope, since the attacker's authenticated boundary (org A) is broken to reach and mutate resources (org B's repository/stacks) outside that boundary.

### Likelihood Explanation
Exploitation requires the attacker to already legitimately hold a `webhook_secret` for at least one organization configured on the Shipit instance (e.g., an org admin, or a compromised GitHub App webhook secret for one tenant) — this is a realistic "unprivileged relative to org B" attacker in a multi-tenant Shipit deployment, since holding org A's secret grants no rights over org B's repositories through GitHub itself, only through this engine's flawed signature-selection logic. No repository write access, `ApiClient` token, or Shipit session is required, satisfying the in-scope threat model.

### Recommendation
After signature verification succeeds, re-derive `repository_owner` from the same trusted context used for the lookup, and additionally verify that the owner segment of `repository.full_name` (and `organization.login` where present) matches the `repository_owner` that selected the verifying secret before dispatching to any handler. Reject the webhook (422) on mismatch.

### Proof of Concept
1. Attacker administers (or has stolen the `webhook_secret` for) GitHub organization `org-a`, configured in `config/secrets.yml` under `github: org-a: webhook_secret: SECRET_A`, alongside an unrelated tenant `org-b/private-repo` tracked by the same Shipit instance.
2. Attacker crafts a `push` (or `status`/`pull_request`) JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/private-repo"
  }
}
```
3. Attacker computes `sha1=HMAC(SECRET_A, body)` and sends it as `X-Hub-Signature`, with `X-Github-Event: push`, to `POST /webhooks`.
4. `verify_signature` resolves `repository_owner` = `"org-a"` from the body, fetches org A's `GitHubApp`, and successfully verifies the signature against `SECRET_A`. [1](#0-0) 
5. `create` dispatches to `PushHandler`, which resolves the target stacks via `repository.full_name` = `"org-b/private-repo"`, and triggers `sync_github` on org B's stack, even though the request was only authenticated for org A. [3](#0-2) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** config/secrets.development.example.yml (L18-34)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
