### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but stack/commit routing trusts the independent, unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')`. Once the signature check passes, the entire raw payload is dispatched unmodified to handlers, which resolve the target `Stack`/`Repository` (or `Commit`) using a *different*, independently-controlled field: `repository.full_name` (or, for `status` events, a bare `sha` lookup with no repository check at all). Because these two fields are never cross-validated, an actor who legitimately controls the webhook secret for one org configured in `Shipit.github` can forge a payload whose `repository.owner.login` matches their own org (so the correct secret is picked and the signature validates) while `repository.full_name` (and thus the resolved `Stack`) points at an entirely different, victim repository/organization hosted on the same Shipit instance.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` computes: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

The lookup and HMAC check are scoped to whichever organization's `webhook_secret` matches `repository.owner.login`. This is the *only* signature check performed; the raw, full JSON payload is then handed to `Shipit::Webhooks.for_event(event)` handlers unmodified: [3](#0-2) 

The base `Handler` class - used by `PushHandler`, `CheckSuiteHandler`, etc. - resolves the affected `Stack`s from a completely separate field of the same payload, `repository.full_name`, never checking it against `repository.owner.login`: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler#process` then directly triggers a sync against the resolved stacks using an attacker-controlled `after` (target SHA): [5](#0-4) 

`StatusHandler` is even weaker: it does no repository scoping at all and updates any `Commit` in the whole database matching an attacker-supplied `sha`: [6](#0-5) 

This breaks the trust binding the rules describe as "an organization that authenticated versus the repository that is written": the identity that is cryptographically authenticated (`repository.owner.login`, used to pick the `webhook_secret`) is not the identity that is acted upon (`repository.full_name`, used to pick the `Repository`/`Stack`, or in the `status` case, no repository check at all).

### Impact Explanation
Any party who legitimately controls a GitHub App/webhook secret for **one** organization configured in `Shipit.github` (a normal, unprivileged capability for an org admin who installs the Shipit GitHub App on their own org in a multi-org Shipit deployment, per `docs/setup.md`'s "Using Multiple Github Applications" configuration) can forge a validly-signed webhook whose `repository.owner.login` is their own org, but whose `repository.full_name` targets a victim org/repo hosted on the same instance. This can:
- Trigger `GithubSyncJob` for an arbitrary victim stack via a forged `push` event with an attacker-chosen `after` SHA, causing the victim stack to sync/attempt to deploy a commit selected by the attacker [5](#0-4) .
- Forge CI `status` updates against any commit database-wide (not even scoped by repository), which can flip a commit's CI state to "success", potentially enabling that commit to satisfy deploy safety checks and be shipped [6](#0-5) .

This maps to "unauthorized deploy" / "cross-repository writes" impact tiers, since a party with credentials scoped to org A can influence deploy-relevant state for org B's stacks.

### Likelihood Explanation
Exploitability only requires knowledge of one org's `webhook_secret` in a multi-organization Shipit deployment - a capability an unprivileged org admin naturally has for their own org, without needing any Shipit session, `ApiClient` token, or elevated Shipit privilege. The request path (`POST /webhooks`) is public/unauthenticated aside from the HMAC check, and no code anywhere cross-validates `repository.owner.login` against `repository.full_name`/`sha` ownership before acting.

### Recommendation
After computing `repository_owner` for signature verification, also derive the repository owner encoded in `repository.full_name` (and, for `status` events, the owner of the repository containing the matched `Commit`) and require it to match `repository_owner` before dispatching to any handler. Alternatively, have handlers resolve the repository via `repository_owner` (the value already verified against the signing secret) rather than trusting `repository.full_name` independently, and scope `StatusHandler`'s `Commit` lookup by the verified repository.

### Proof of Concept
1. Shipit is configured with two GitHub orgs, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (per the documented "Using Multiple Github Applications" setup) [7](#0-6) ; the attacker is an admin of `attacker-org` and thus knows `attacker-org`'s `webhook_secret`.
2. `victim-org/victim-repo` has a `Stack` already configured in this Shipit instance.
3. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over the raw JSON body, and sends `POST /webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner == "attacker-org"`, fetches `attacker-org`'s `webhook_secret`, and the HMAC check passes (the attacker signed correctly with a secret they legitimately possess) [1](#0-0) .
6. `PushHandler.call(params)` runs; `repository_name` returns `"victim-org/victim-repo"`, resolving `victim-org/victim-repo`'s stacks and calling `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on a stack the attacker has no legitimate relationship to [4](#0-3) [5](#0-4) .

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** docs/setup.md (L184-209)
```markdown
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
