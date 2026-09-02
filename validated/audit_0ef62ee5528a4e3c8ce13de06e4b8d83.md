### Title
Webhook signature verified against `repository.owner.login` while the event is processed against a different `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization used to validate the HMAC signature from `params.dig('repository', 'owner', 'login')` (or `organization.login`), while the handler that actually executes the event (`Handler#stacks` / `Handler#repository_name`) resolves the target `Repository`/`Stack` from a completely different payload field, `payload.dig('repository', 'full_name')`. These two fields are never checked against each other, so the "organization whose secret authenticated the request" and the "repository whose stacks get acted upon" are two independent, attacker-controlled bindings.

### Finding Description
`before_action :check_if_ping, :drop_unhandled_event, :verify_signature` runs `verify_signature`, which does: [1](#0-0) 
using `repository_owner`: [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the per-organization webhook secret (multiple orgs/apps can be configured, each with its own `webhook_secret`, as shown by `lib/shipit/github_app.rb`'s per-org `@webhook_secret`) and calls `verify_webhook_signature`: [3](#0-2) 

Once the signature passes, `create` dispatches the parsed JSON body to the matching handler(s): [4](#0-3) 

Every handler resolves the target stacks purely from `repository.full_name`, not from `repository.owner.login`: [5](#0-4) 
which is then used, e.g. in `PushHandler`, to trigger a sync of any stack whose branch matches: [6](#0-5) 
and `Repository.from_github_repo_name` simply splits `owner/name` out of that string with no cross-check against `repository.owner.login`: [7](#0-6) 

Because the signing secret is selected by `repository.owner.login`/`organization.login`, but the acted-upon repository is selected by the independent `repository.full_name` field, an attacker who legitimately controls (or has push/webhook-trigger rights in) organization A can craft a raw JSON body where `repository.owner.login = "orgA"` (so the HMAC is computed and verified with orgA's secret) while `repository.full_name = "orgB/some-repo"`. The signature check passes because it never inspects `full_name`, and the handler then acts on stacks belonging to `orgB`'s repository — an organization the attacker never authenticated against.

This is the same class of bug as the audited `DnGmxJuniorVault` finding: a verified/trusted value (there: `state.protocolEsGmx` snapshotted for an external call) is decoupled from the value actually acted upon afterward, letting a party who only controls one side of the binding manipulate the other. Here the "verified/authorizing" field (`repository.owner.login`) is decoupled from the "acted upon" field (`repository.full_name`), i.e., "an organization that authenticated versus the repository that is written."

### Impact Explanation
This lets an attacker who only holds legitimate webhook-trigger capability for organization A (e.g., is a collaborator able to push/open PRs there, or otherwise can get orgA's webhook to fire with attacker-influenced body content, or directly knows orgA's shared webhook secret because they administer a repo under it) force Shipit to process fabricated GitHub events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) against stacks/repositories belonging to an unrelated organization B whose secret was never checked. Depending on handler, this can enqueue `GithubSyncJob`/`RefreshCheckRunsJob` for orgB's stacks, forge commit statuses on orgB's commits, or manipulate `pull_request`/`membership` state — a cross-repository/cross-organization write triggered by a party never authenticated for that organization.

### Likelihood Explanation
Exploitability depends on the attacker being able to produce a raw JSON body whose `repository.full_name` differs from `repository.owner.login`/`organization.login` while getting it signed with a secret they know (their own org's webhook secret, or any org configured in this Shipit instance). In a single-organization deployment this is not exploitable (owner login always matches the acted-upon repo). It becomes concretely exploitable in any multi-organization Shipit deployment (explicitly supported — see `test/dummy/config/secrets_double_github_app.yml` multiple orgs configuration) where different organizations have distinct webhook secrets but the events all funnel through the same `WebhooksController`.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), assert that the organization/owner used to select the verifying secret is the same value used to resolve the target repository — e.g., compare `params.dig('repository', 'owner', 'login')` against the owner portion of `params.dig('repository', 'full_name')` (and reject/422 on mismatch) before dispatching to handlers, rather than trusting the two independently-controlled payload fields to agree.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own `webhook_secret` (as supported per `lib/shipit/github_app.rb` config and demonstrated in `test/dummy/config/secrets_double_github_app.yml`).
2. As an attacker who knows/controls `orgA`'s webhook secret (e.g., is able to configure or trigger a webhook delivery for a repo under `orgA`), craft a raw JSON push payload body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/target-repo"
  }
}
```
3. Sign the raw body with `orgA`'s `webhook_secret` and send it as `X-Hub-Signature` with header `X-Github-Event: push` to `POST /webhooks`.
4. `verify_signature` computes `repository_owner = "orgA"`, fetches `orgA`'s app, and successfully verifies the signature.
5. `create` dispatches the payload to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("orgB/target-repo")` and enqueues `GithubSyncJob` for `orgB`'s stack — a cross-organization action the attacker never authenticated for.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
