### Title
Webhook signature key is selected from `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` field — a signed tenant can forge cross-tenant events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is a direct analog of the `dexAllowlist` bug: the report's root cause is that three related values (`approveTo`, `callTo`, `callData` signature) are checked *independently* instead of being bound together as a single verified triple, letting an attacker mix a value that passed one check with an unrelated value that passed a different check. In Shipit, the webhook-verification path exhibits the same "independent-checks" pattern: the field used to *select the cryptographic key* for signature verification (`repository.owner.login`, resolved via `Shipit.github(organization: ...)`) is never bound to the field that event handlers actually use to decide *which repository/stack* to act on (`repository.full_name`). A tenant that legitimately controls one GitHub organization configured in a multi-org Shipit deployment can therefore craft a payload that is validly signed for their own organization key, while pointing `repository.full_name` at a completely different organization's repository/stack.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization solely from the untrusted JSON body and uses it to pick the `GitHubApp`/`webhook_secret` used for HMAC verification: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`) purely from the body content, then looks up the corresponding `GitHubApp` config (`Shipit.github(organization: repository_owner)`) and verifies `X-Hub-Signature` against that org's `webhook_secret`: [3](#0-2) 

After the signature check succeeds, `create` dispatches the parsed body to the event handler: [4](#0-3) 

Every handler, however, resolves the *actual repository/stack to act on* from a different field of the same body — `repository.full_name` — with no cross-check against the `repository.owner.login` value that gated signature verification: [5](#0-4) [6](#0-5) 

The Shipit docs explicitly describe a supported multi-tenant configuration where distinct GitHub organizations each have their own `app_id`/`webhook_secret` under `Shipit.github`: [7](#0-6) 

Because each organization's admin legitimately knows their own `webhook_secret` (they configured it), a member of "OrgA" can compute a valid `X-Hub-Signature` over an arbitrary JSON body of their own choosing (nothing requires the body to originate from GitHub — the controller simply HMAC-verifies whatever raw body was POSTed) with `repository.owner.login = "OrgA"` (so `verify_signature` selects and validates against OrgA's own secret) while setting `repository.full_name = "OrgB/target-repo"` (so the dispatched handler acts on OrgB's stack). The binding that should hold — *the organization whose key authenticated the payload* == *the repository the payload is permitted to mutate* — is never enforced; only the former is checked, and the latter is trusted unconditionally.

### Impact Explanation
This lets an unprivileged member of any one configured GitHub organization forge webhook events against any *other* tenant repository hosted on the same Shipit instance, without holding that other org's webhook secret, an `ApiClient` token, or GitHub write access to the target repo. Depending on the forged event (`push`, `status`, `check_suite`, `pull_request`, `membership`), the attacker can: enqueue `GithubSyncJob`/`stack.sync_github` on a victim stack with an attacker-chosen `expected_head_sha` (which can drive continuous-delivery deploy scheduling once the sha is fetched from GitHub), inject/forge `Status`es to unblock CI-gated deploys, or manipulate victim `PullRequest`/`ReviewStack` state (archive/unarchive, label-driven provisioning) — all cross-tenant actions that should require that tenant's own credentials. This maps to the "organization that authenticated versus the repository that is written" trust-binding break called out in scope, with impact reaching cross-repository/cross-tenant writes and unauthorized deploy scheduling.

### Likelihood Explanation
Requires only that the attacker be an authenticated administrator/holder of the webhook secret for *any one* organization configured in a multi-org Shipit deployment — a low bar relative to compromising another tenant's secret, GitHub write access, or an `ApiClient` token. Single-organization deployments (the common case, one `webhook_secret` for the whole instance) are not affected by cross-tenant forgery since there is only one key, but the vulnerable code path (unbound `owner.login` vs `full_name`) is unconditional and present regardless of deployment topology.

### Recommendation
Bind the field used to select the verification key to the field used for authorization/dispatch. After selecting `github_app` from `repository_owner`, re-validate that `payload.dig('repository','full_name')` actually belongs to that same organization (e.g., assert `full_name.split('/').first == repository_owner`, or resolve the `Repository`/`Stack` and check its owning organization matches `repository_owner`) before invoking any handler. Alternatively, avoid deriving the signing key from attacker-controlled payload content at all — verify against every configured secret and require exactly one to match, then treat the matching organization as authoritative for that request, rejecting payloads whose `repository.full_name` organization doesn't match.

### Proof of Concept
1. Multi-org Shipit deployment where organization `OrgA` (attacker-controlled) and `OrgB` (victim) are both configured under `Shipit.github`, each with distinct `webhook_secret`s, per `docs/setup.md` "Using Multiple Github Applications".
2. Attacker (an admin of OrgA's GitHub App) knows OrgA's `webhook_secret` and computes:
   ```
   body = {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
   }.to_json
   signature = "sha1=" + HMAC-SHA1(OrgA_webhook_secret, body)
   ```
3. POST to `/webhooks` with headers `X-Github-Event: push`, `X-Hub-Signature: signature`, body as above.
4. `verify_signature` computes `repository_owner = "OrgA"`, fetches OrgA's `GitHubApp`, and validates the signature successfully against the attacker-supplied body (since it was computed with OrgA's real secret).
5. `WebhooksController#create` dispatches to `PushHandler`, whose `Handler#stacks` resolves `Repository.from_github_repo_name("OrgB/victim-repo")` — an org the attacker never authenticated as — and enqueues `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on OrgB's stack, per `app/models/shipit/webhooks/handlers/handler.rb:30-38` and `app/models/shipit/webhooks/handlers/push_handler.rb:12-17`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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
