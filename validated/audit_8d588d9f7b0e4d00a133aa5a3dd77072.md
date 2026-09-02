### Title
GitHub webhook organization used for signature verification is decoupled from the repository the payload acts on, enabling cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`), but the handlers that actually act on the payload resolve the target repository from the independent `repository.full_name` field. Because these two fields are never cross-checked, an attacker who legitimately controls a GitHub App/org configured in the same Shipit instance can sign a payload with their own `webhook_secret` while naming an arbitrary victim repository as the target of the write.

### Finding Description
`WebhooksController#verify_signature` picks the `Shipit.github` app instance to verify against using: [1](#0-0) 
This drives which `webhook_secret` is used to validate `X-Hub-Signature`: [2](#0-1) 

Once the signature check passes, the event is dispatched to a handler: [3](#0-2) 

The base `Handler` class, and concrete handlers like `PushHandler`, resolve the target `Stack`/`Repository` from a *different* payload field — `repository.full_name` — with no comparison back to `repository.owner.login` used for signature verification: [4](#0-3) [5](#0-4) 

In a multi-organization Shipit deployment (explicitly supported and documented), each org has its own independently-configured `webhook_secret`: [6](#0-5) 

Because HMAC verification only proves "this body was signed with OrgA's secret," and the handler logic trusts `repository.full_name` unconditionally to select which stack/repository is mutated, an attacker who is the legitimate owner/administrator of OrgA's GitHub App (and thus knows OrgA's `webhook_secret`, since app owners set this value themselves per `docs/setup.md`) can forge a payload where `repository.owner.login = "OrgA"` (to pass verification with a secret they know) but `repository.full_name = "victim-org/victim-repo"` (to target a completely different, unrelated repository/stack configured in the same Shipit instance).

This breaks the binding: **organization that authenticated == repository that is written**. The verified identity (OrgA) and the acted-upon repository (victim-org/victim-repo) are never required to match.

### Impact Explanation
This allows cross-organization/cross-repository writes without any credential belonging to the victim org: an attacker with only a legitimate, unprivileged GitHub App on their own org can trigger `GithubSyncJob`/`sync_github` and other webhook-driven mutations (status updates via `StatusHandler`, check-suite refreshes, PR label/state handlers, membership/team creation, etc.) against stacks belonging to a completely different repository/organization also hosted on the shared Shipit instance. Depending on which event is forged (e.g., `status`), this can be used to inject fabricated CI state onto arbitrary commit SHAs of a victim repository, which can influence deploy-safety checks (`deployable?`) that a legitimate deployer of that other stack relies on — i.e., a cross-repository write culminating in the possibility of an unauthorized/unsafe deploy path being unblocked. This matches the Critical impact bucket ("cross-repository writes" / contributing to "an unauthorized deploy").

### Likelihood Explanation
Likelihood is realistic in any Shipit deployment that follows the documented multi-organization setup (`docs/setup.md` "Using Multiple Github Applications"), which is an explicitly supported and encouraged configuration for hosting several orgs/teams on one Shipit instance. Any org owner in that shared instance — an otherwise unprivileged actor with respect to other orgs' repositories — can exploit this purely by crafting a raw HTTP POST to `/webhooks` with a valid signature for their own org and a `repository.full_name` pointing elsewhere; no GitHub write access or Shipit session/token is required.

### Recommendation
After successfully verifying the signature for organization `O`, the handler dispatch path should reject (or additionally verify) any payload whose `repository.full_name`'s owner segment does not match the organization `O` that produced a valid signature. Concretely, `WebhooksController#create`/`Handler#repository_name` should assert `repository.full_name.split('/').first == repository_owner` (the same organization resolved in `verify_signature`) before invoking any handler, returning `422` otherwise.

### Proof of Concept
1. Attacker administers `OrgA`'s GitHub App connected to the shared Shipit instance and knows `OrgA`'s `webhook_secret` (set by them per `docs/setup.md`).
2. Attacker crafts a `push` webhook JSON body with `repository.full_name = "victim-org/victim-repo"` and `repository.owner.login = "OrgA"`.
3. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#repository_owner` resolves to `"OrgA"` [1](#0-0) , `Shipit.github(organization: "OrgA")` is used, and the signature verifies successfully.
5. `PushHandler#process` is invoked and resolves `stacks` from `payload.dig('repository','full_name')` = `"victim-org/victim-repo"` [4](#0-3) , triggering `stack.sync_github` for a stack the attacker has no relationship to, despite the signature only proving control of `OrgA`.

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
