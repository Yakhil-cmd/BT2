### Title
Webhook signature verification is keyed off an attacker-controlled `repository.owner.login`, decoupled from the repository/stacks the payload actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate the HMAC signature against using `repository_owner`, a value read directly out of the *unverified* JSON body (`params.dig('repository', 'owner', 'login')`). The handlers that subsequently act on the payload (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) select the stacks to mutate using a *different* field from the same unverified body: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together. This is the same root-cause pattern as M-36: a security-relevant decision (“is this authentic?”) is made against one interpretation of attacker-supplied data (`instructionCount`/`repository.owner.login`), while the actual state-changing action is performed against a different, uncoupled interpretation of the same attacker-supplied blob (the “gateway instruction”/`repository.full_name`).

### Finding Description [1](#0-0)  shows `create` parsing the raw body once and dispatching it, unmodified, to every registered handler for the event: [2](#0-1)  shows `verify_signature`: it computes `repository_owner` from the payload and asks `Shipit.github(organization: repository_owner)` for the app/secret to validate the HMAC against. [3](#0-2)  shows that `repository_owner` is read straight from the JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [4](#0-3)  shows `verify_webhook_signature` returns `true` unconditionally when the resolved app has no `webhook_secret` configured (`return true unless webhook_secret`). The repo's own multi-org fixture demonstrates this is an expected, supported configuration, not a misconfiguration: [5](#0-4) .

Meanwhile the handlers act on a *different* field of the same untrusted body. `Handler#repository_name` reads `payload.dig('repository', 'full_name')`: [6](#0-5) . `PushHandler#process` uses that to select `stacks` and calls `stack.sync_github(expected_head_sha: params.after)`: [7](#0-6) . `StatusHandler#process` is even less scoped — it matches purely by `sha` across *all* commits in the datastore with no repository filter at all: [8](#0-7) .

Because `repository.owner.login` (used for auth) and `repository.full_name` (used for the write) are independent, attacker-controlled strings within the same JSON body, an attacker can set them to point at two different organizations/repositories. If any organization configured in the Shipit installation has no `webhook_secret` set (a documented, supported setup — see the multi-org docs and fixture cited above), an attacker can:
1. Set `repository.owner.login` / `organization.login` to that unsecured organization so `verify_signature` resolves an app whose `verify_webhook_signature` always returns `true`.
2. Set `repository.full_name` to `victim-org/victim-repo` (any repo tracked by any Shipit stack, entirely unrelated to the unsecured org) and `sha` to a real commit sha of that victim stack (shas are public GitHub data).

The request passes signature verification (using the unsecured org's app, which never checks a secret) yet the handler mutates state for the victim repository/stack.

### Impact Explanation
This breaks the exact equality the check is supposed to enforce: `organization that authenticated == repository that is written`. Concretely:
- Via the `status` event, an attacker can inject arbitrary commit statuses (`state: success`) for any commit sha in any stack (`StatusHandler` has no repository scoping at all), which can satisfy `ci.require`/blocking-status gates used by the merge queue and continuous delivery to authorize merges and deploys — an **unauthorized deploy/merge** condition.
- Via the `push` event, an attacker can force `GithubSyncJob` to run for stacks unrelated to the "authenticating" organization, expanding the blast radius of a single misconfigured (secret-less) org to every stack in the installation.

This satisfies the Critical/High impact bar ("an unauthorized deploy, rollback or merge") because the trust binding between the entity whose secret validated the request and the entity whose data gets mutated is not enforced anywhere in the request-processing pipeline.

### Likelihood Explanation
The precondition is that at least one configured GitHub organization in the multi-org setup lacks a `webhook_secret`. This is explicitly documented as a supported configuration (the `webhook_secret` field is optional per `docs/setup.md`, and the shipped test fixture `secrets_double_github_app.yml` configures two organizations both with `webhook_secret: # nil`). Any installation with a mix of secured and unsecured GitHub App installations — which the engine's own multi-org configuration format anticipates — is exposed. No GitHub account, repository access, or Shipit session is required; the attacker only needs to know a target stack's `owner/repo` full name and a commit sha, both of which are public GitHub information.

### Recommendation
Do not let handlers act on `repository.full_name`/commit shas that were never covered by the identity used to select the verification secret. Concretely: after resolving `repository_owner` and verifying the signature, cross-check that `repository.full_name` actually belongs to that same verified organization (e.g. `full_name.split('/').first == repository_owner`) before dispatching to handlers, and reject (422) on mismatch. Additionally, scope `StatusHandler` (and any handler matching by `sha` alone) to the repository identified in the payload rather than searching all commits/stacks globally.

### Proof of Concept
1. Configure two GitHub App organizations in `secrets.yml`: `UnsecuredOrg` (no `webhook_secret`) and `VictimOrg` (properly secured, hosting a tracked stack `VictimOrg/victim-repo`).
2. As an unauthenticated attacker, `POST /github_webhooks` (no valid `X-Hub-Signature` needed) with header `X-Github-Event: status` and body:
```json
{
  "sha": "<real sha of a commit in the VictimOrg/victim-repo stack>",
  "state": "success",
  "context": "ci/required-check",
  "organization": { "login": "UnsecuredOrg" },
  "repository": { "owner": { "login": "UnsecuredOrg" }, "full_name": "VictimOrg/victim-repo" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "UnsecuredOrg")`, whose `verify_webhook_signature` returns `true` unconditionally (no secret configured), so the request is accepted.
4. `StatusHandler#process` matches `Commit.where(sha: params.sha)` (no repository scoping) and records a passing status for the victim's commit, potentially satisfying required-status gates used by the merge queue/continuous delivery for `VictimOrg/victim-repo` — despite the attacker having no relationship to `VictimOrg` at all.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
