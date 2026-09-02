### Title
Cross-organization webhook forgery via unsecured org config lets `pull_request unlabeled` payloads mutate another repo's `PullRequest` labels - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`WebhooksController#verify_signature` derives the GitHub App/org used for signature verification solely from `params.dig('repository','owner','login')` in the attacker-controlled JSON body, while `LabelCapturingHandler`/`ReviewStackAdapter` resolve the actual `Repository`/`Stack` to mutate from a separate, independently attacker-controlled field: `params.repository.full_name`. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the org's `webhook_secret` is blank [1](#0-0) . Because nothing in the schema or controller ties `repository.owner.login` to `repository.full_name`'s owner, an attacker who controls (or can name) any org configured in Shipit with no `webhook_secret` can forge a body whose `repository.full_name` points at a completely different, secret-protected org's repository, and the request is accepted and processed.

### Finding Description
The broken binding: the organization whose credentials verified the request (`repository_owner = params.dig('repository','owner','login')`, used in `Shipit.github(organization: repository_owner)`) must equal the organization that owns the repository/stack actually mutated (`Shipit::Repository.from_github_repo_name(params.repository.full_name)`'s owner). These are two independent fields read from the same attacker-supplied JSON body and are never cross-checked.

Path:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` and calls `github_app.verify_webhook_signature(signature, raw_post)` [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` returns `true unless webhook_secret` — i.e., if the org resolved in step 1 has no `webhook_secret` configured, verification is bypassed entirely regardless of the `X-Hub-Signature` header or body content [3](#0-2) .
3. `WebhooksController#create` then dispatches the same raw JSON body to `Shipit::Webhooks.for_event(event)` handlers [4](#0-3) .
4. `LabelCapturingHandler#repository` resolves the target repository from `params.repository.full_name` — a field distinct from `repository.owner.login` used in step 1 — via `Shipit::Repository.from_github_repo_name` [5](#0-4) .
5. `#capture_labels` then does `pull_request.update!(labels: params.pull_request.labels.map(&:name))` on the stack's `PullRequest` for whatever repository `full_name` resolved to [6](#0-5) .

The handler's `ExplicitParameters` schema requires `repository.full_name` but has no constraint that `repository.owner.login` matches its owner segment, and no such field is required at all in the schema (`owner` is never declared) [7](#0-6) . Thus an attacker crafts: `repository: { full_name: "victim-org/victim-repo", owner: { login: "attacker-controlled-no-secret-org" } }`, plus a valid `pull_request`/`sender` block. If `attacker-controlled-no-secret-org` is configured in Shipit (e.g., a legitimately onboarded org that simply hasn't set a `webhook_secret` yet, or any org name Shipit resolves without raising `GithubOrganizationUnknown`), `verify_signature` passes trivially, and the handler mutates `victim-org/victim-repo`'s actual `PullRequest.labels`, which later becomes uppercased environment keys via `ReviewStack#env`.

Existing guards do not catch this: `verify_signature` only checks HMAC using the wrong-scoped org; `ExplicitParameters` validates shape, not cross-field consistency; `drop_unhandled_event` only checks the event type is registered; there is no model validation binding `Repository#full_name`'s org segment to the org used for webhook verification.

### Impact Explanation
An attacker controlling (or simply naming) any single Shipit-configured GitHub organization lacking a `webhook_secret` can forge `pull_request` webhook payloads that write to a completely different tenant's `PullRequest` record — mutating `labels`, which feed into `ReviewStack#env` and thus the deploy-time environment for that other org's review stack. This is a cross-repository/cross-tenant state manipulation matching the Critical severity category ("a payload for one repository mutating another's stack, commit, task or team"). It is repeatable against any repository/stack in the system as long as one no-secret org exists in the Shipit-wide GitHub App configuration.

### Likelihood Explanation
Preconditions: at least one org configured in `Shipit.github_apps`/`Shipit.github(organization:)` config must have a blank `webhook_secret` (a plausible misconfiguration/onboarding gap, not requiring attacker secrets). Given that, the attacker needs no Shipit credentials, no `webhook_secret`, and no GitHub push access to the victim repo — only the ability to send an HTTP POST to `/webhooks` with a crafted JSON body and matching `X-Github-Event: pull_request` header. Cost is trivial and fully repeatable.

### Recommendation
Bind signature verification to the same repository/organization that the handler will act on: derive `repository_owner` strictly from `repository.full_name`'s owner segment (single source of truth used both for `Shipit.github(organization:)` lookup and for handler repository resolution), and/or make `GitHubApp#verify_webhook_signature` fail closed (reject, not accept) when `webhook_secret` is blank, rather than treating an absent secret as "verification not required."

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, illustrative):
1. Configure two orgs in `Shipit.github_apps`/config stub: `"attacker-org"` with no `webhook_secret`, and `"victim-org"` with a real `webhook_secret`.
2. Create `victim_repo = Shipit::Repository.create!(name: "victim-repo", owner: "victim-org", ...)`, a `Shipit::ReviewStack` under it with `environment: "pr123"`, and its `PullRequest` with `labels: []`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no valid `X-Hub-Signature` for `victim-org`'s secret, and body:
   ```json
   {
     "action": "unlabeled",
     "number": 123,
     "pull_request": { ..., "labels": [{"name": "malicious-env-key"}] },
     "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } },
     "sender": { "login": "attacker" }
   }
   ```
4. Assert response is `200 OK` (not `422`) — proving `verify_signature` used `attacker-org`'s (no-secret) config, i.e. `repository_owner` binding ≠ `repository.full_name` owner binding.
5. Reload `victim_repo`'s stack's `pull_request` and assert `labels == ["malicious-env-key"]` — proving the forged payload mutated `victim-org`'s record despite the signature/org used for verification being `attacker-org`.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```
