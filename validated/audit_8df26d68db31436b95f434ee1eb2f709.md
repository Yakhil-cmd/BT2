### Title
Webhook signature is verified against the organization named in the payload, but the `status` handler writes to any commit matching a global SHA regardless of that organization - cross-organization forged CI status enabling unauthorized deploys - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` picks *which* per-organization `webhook_secret` to verify a payload against using an attacker-controlled field inside the very payload being verified, while `StatusHandler` (and other handlers) act on data that is never checked against that same organization. This breaks the trust binding: `organization authenticated (used to pick webhook_secret) == repository/commit actually written to`.

### Finding Description
In a multi-tenant Shipit deployment (documented in README "Using Multiple Github Applications" and exercised by `test/dummy/config/secrets_double_github_app.yml`), each GitHub organization configured in `secrets.yml` has its **own independent `webhook_secret`** [1](#0-0) .

`WebhooksController#verify_signature` selects which organization's `GitHubApp` (and therefore which `webhook_secret`) to verify the signature against by reading `repository.owner.login` (or `organization.login`) straight out of the *unverified* JSON body: [2](#0-1) [3](#0-2) 

`GitHubApp#verify_webhook_signature` then HMACs the raw body with the secret for that self-declared organization: [4](#0-3) 

Because the attacker fully controls the raw JSON body, they can set `repository.owner.login` to an organization whose `webhook_secret` they know (e.g., their own org configured on the same Shipit instance, which they legitimately administer), producing a signature that will pass verification.

The event is then dispatched to handlers purely by `X-Github-Event`, with no re-check that the organization used for verification matches the data the handler operates on. `StatusHandler` is the most dangerous case: its param schema only requires `sha` and `state` — it does **not** even parse or validate a `repository` field — and its `process` method updates status for **every** `Commit` in the entire datastore whose `sha` matches, irrespective of stack/repository/organization: [5](#0-4) 

This forged status is written via `Commit#create_status_from_github!` → `add_status`, which recomputes `deployable?` and can immediately trigger `schedule_continuous_delivery`: [6](#0-5) [7](#0-6) [8](#0-7) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated via webhook_secret (repository.owner.login in payload) == organization owning the repository/commit actually mutated by the handler (sha lookup, global across all stacks)`

Before the attacker's request: Org A's webhook_secret only ever authenticates events that are legitimately about Org A repositories (GitHub itself guarantees this on the real webhook delivery path, since GitHub signs the payload it generates and only sends Org A payloads through Org A's configured secret).

After the attacker's request: an entity that only knows Org A's `webhook_secret` can produce a validly-signed payload whose *content* (`sha`, `state`, etc., for `status` events) targets a commit belonging to Org B's stack, because `StatusHandler` never re-derives or checks organization/repository ownership from the SHA before writing.

### Impact Explanation
This is a High/Critical-impact cross-tenant break: an attacker who legitimately controls the webhook_secret for **one** organization configured on a shared Shipit instance can forge a `success` (or any) CI status for an arbitrary commit SHA belonging to a **different** organization's stack. If that stack has `continuous_deployment` enabled or its required status checks include the forged context, this directly triggers `schedule_continuous_delivery` and can cause an **unauthorized deploy** of an unreviewed/unintended commit in a repository the attacker does not control — matching the "unauthorized deploy" Critical/High impact criterion, and effectively an authentication-boundary bypass: an organization's webhook credential is being treated as authorization to write into a completely different organization's data.

### Likelihood Explanation
This requires the deployment to use the multi-organization `github:` config format (explicitly documented and tested as a supported configuration) and requires the attacker to know/control the `webhook_secret` for at least one organization on the shared instance — a realistic scenario for any Shipit installation shared across several orgs/teams (e.g., an internal platform team hosting Shipit for multiple business units, each with delegated ability to configure their own GitHub App/webhook_secret). No GitHub App private key, TLS interception, or Shipit session is needed — only knowledge of one tenant's webhook secret, which is a much lower privilege than the target organization's credentials.

### Recommendation
- Do not select the verification secret from an unauthenticated field of the same payload being verified. Alternatively, after selecting a candidate organization and verifying the signature, cross-check that every organization/repository-identifying field used by the dispatched handler (e.g., `repository.full_name` / `repository.owner.login`) is consistent with the organization whose secret validated the request.
- In `StatusHandler` (and similarly in any handler that doesn't already scope by repository), require and parse a `repository.full_name`, resolve the `Repository`/`Stack` via `Repository.from_github_repo_name`, and only update statuses for commits belonging to that specific repository/stack, rejecting the event if the resolved repository's owner does not match the organization used in `verify_signature`.

### Proof of Concept
1. Shipit is configured with the multi-org `github:` format, e.g. `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker administers a GitHub App for `OrgA` (or otherwise knows `OrgA`'s `webhook_secret`) but has no access to `OrgB`.
3. Attacker crafts a `status` event JSON body:
   ```json
   {
     "sha": "<sha of an undeployed commit on an OrgB stack>",
     "state": "success",
     "context": "required-ci-check",
     "repository": { "owner": { "login": "OrgA" } }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` reads `repository.owner.login == "OrgA"`, loads `Shipit.github(organization: "OrgA")`, and the signature verifies successfully [9](#0-8) .
6. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which looks up `Commit.where(sha: params.sha)` — the OrgB commit — with no organization check, and calls `create_status_from_github!`, marking it successful [10](#0-9) .
7. If the OrgB stack has continuous deployment enabled, `Commit#schedule_continuous_delivery` fires and the commit is deployed, even though the attacker never had any credential for OrgB.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
