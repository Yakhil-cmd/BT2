### Title
Webhook signature is verified against `repository.owner.login`, but events are applied to the repository named in `repository.full_name` - cross-organization stack takeover ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/HMAC secret to validate a webhook using `repository.owner.login` (falling back to `organization.login`) taken from the raw, attacker-suppliable JSON body, then hands the *entire* unmodified payload to the event handlers. The handlers, however, resolve the target `Repository`/`Stack` using a different field of the same payload: `repository.full_name`. Because Shipit explicitly supports hosting multiple GitHub organizations with independent `webhook_secret`s on a single instance, a party who legitimately knows the webhook secret for *one* configured organization can forge a signature that verifies successfully for that organization while setting `repository.full_name` to point at a stack belonging to a *different* configured organization/repository, and have the handler act on it.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

and uses it to pick the app/secret for HMAC verification:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
``` [2](#0-1) 

Once verified, the raw parsed JSON (`params`) is passed unmodified to every registered handler:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

But the base `Handler` (and every event handler built on it, e.g. `PushHandler`) resolves the repository/stack to mutate using a *different* JSON field, `repository.full_name`, not `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`PushHandler` then queues a `GithubSyncJob` against those stacks using the attacker-controlled `after` SHA:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

The same pattern repeats in every pull-request handler, which independently resolve `repository` via `params.repository.full_name` (e.g. `OpenedHandler#repository`, `ClosedHandler#repository`), completely decoupled from the field used for signature routing: [6](#0-5) [7](#0-6) 

Shipit explicitly supports configuring multiple GitHub organizations, each with its own independent `webhook_secret`, on the same instance: [8](#0-7) 

Because the code that decides "which secret authenticated this request" (`repository.owner.login`) is never cross-checked against the code that decides "which repository/stack this request mutates" (`repository.full_name`), the binding `authenticated_org == written_repository_org` does not hold. An attacker who legitimately controls (and thus knows the webhook secret of) any one org configured on the same Shipit deployment can sign a payload whose `repository.owner.login` is their own org (so the HMAC check passes with their own secret) while setting `repository.full_name` to `"other-org/other-repo"`, causing Shipit to run handler logic (sync stacks, create/archive review stacks, update PR state, post commit statuses) against a repository/organization they do not administer.

### Impact Explanation
This breaks the deployment-trust binding "an organization that authenticated versus the repository that is written," explicitly called out as in-scope. Concretely, a party with legitimate webhook credentials for Org A but no privileges on Org B's Shipit stacks can:
- Trigger `GithubSyncJob` / forced resyncs on Org B's stacks with an attacker-chosen `expected_head_sha` (`PushHandler`), influencing which commit Shipit believes is deployable for another org's repository.
- Force-create, archive, or unarchive Org B's review stacks via forged `pull_request` events (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.), since these only key off `repository.full_name`.
- Inject fabricated commit statuses/check-run state for Org B's commits, which Shipit's deploy safety checks (`ci.require`) rely on to gate real deploys.

This is a cross-repository, cross-organization write achieved purely by owning a *different, legitimately configured* org's webhook secret — no session, `ApiClient` token, or GitHub App private key for the victim org is required, satisfying the High-severity bar ("escalation ... unauthenticated read of stack state," and bordering on Critical since it can influence what commit is considered deployable / an unauthorized change to deploy-gating state for a repository the caller does not control).

### Likelihood Explanation
Requires the Shipit instance to be configured with more than one GitHub organization (a documented, supported configuration — see `config/secrets.development.shopify.yml` and `docs/setup.md`), and the attacker must legitimately administer at least one of those organizations' GitHub Apps (hence knows its `webhook_secret`, which they are entitled to as that org's own operator). No other authentication or privilege on the victim org/repository is needed, and the payload can be crafted and POSTed by anyone able to reach `/webhooks` with a valid signature for their own org — a realistic, low-privilege multi-tenant scenario.

### Recommendation
After signature verification, re-derive and enforce that the organization used to select the verifying secret (`repository.owner.login` / `organization.login`) matches the organization implied by `repository.full_name` (and any other repository identifiers the handlers use) before dispatching to handlers. Reject the webhook (422) on mismatch. Alternatively, have handlers resolve repositories scoped to the already-verified `repository_owner` rather than trusting `full_name` independently.

### Proof of Concept
1. Shipit is deployed with two orgs configured, `org-a` and `org-b`, each with a distinct `webhook_secret` (per `config/secrets.development.shopify.yml` schema).
2. Attacker legitimately administers `org-a`'s GitHub App and therefore knows `org-a`'s `webhook_secret`.
3. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
4. Attacker computes `X-Hub-Signature` using `org-a`'s `webhook_secret` over the raw body and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` looks up `Shipit.github(organization: "org-a")` (from `repository.owner.login`) and the HMAC verifies successfully.
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name("org-b/victim-repo")` and enqueues `GithubSyncJob` with the attacker-supplied `expected_head_sha` against `org-b`'s stack, even though the attacker only authenticated as `org-a`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

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
