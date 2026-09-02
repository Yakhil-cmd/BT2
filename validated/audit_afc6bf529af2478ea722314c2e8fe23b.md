Confirmed: `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank [1](#0-0) . Combined with `WebhooksController#repository_owner`, which independently derives the org used for signature verification from `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) , while `LabelCapturingHandler` derives the target repository from the separate `params.repository.full_name` field [3](#0-2) , this is a real divergence between the verification identity and the write identity.

### Title
Forged `pull_request` "labeled" webhook bypasses signature verification via organization/repository field divergence, causing cross-tenant `PullRequest` mutation - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/org (and thus the `webhook_secret` used for HMAC verification) from `repository.owner.login`, falling back to `organization.login` if the repository's owner sub-key is absent from the payload [4](#0-3) . `LabelCapturingHandler`, however, resolves the target `Repository`/`Stack`/`PullRequest` to mutate from the independent `repository.full_name` field [5](#0-4) . An attacker who controls an org configured with no `webhook_secret` can craft a payload where `repository.full_name` points at a victim repo while `repository.owner.login` is omitted so the fallback selects the attacker's own (secret-less) org, satisfying `verify_webhook_signature` trivially since it returns `true` when `webhook_secret` is blank [1](#0-0) .

### Finding Description
The broken binding: `organization_that_verified_request == organization_that_owns_the_written_repository` should always hold, but is not enforced.

- Verification identity: `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) . This value is passed to `Shipit.github(organization: repository_owner)` to pick the `GitHubApp` instance and its `webhook_secret`, then `github_app.verify_webhook_signature(...)` runs the HMAC check [6](#0-5) .
- Write identity: `LabelCapturingHandler#repository` calls `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [7](#0-6) , and `capture_labels` calls `pull_request.update!(labels: params.pull_request.labels.map(&:name))` on the resolved stack's `PullRequest` [8](#0-7) .

These two lookups read from different keys under `repository` (`repository.owner.login` vs `repository.full_name`), so they can be made to diverge as long as `repository.full_name` is still present (the handler's `ExplicitParameters` schema `requires :repository do requires :full_name, String end`) — the schema does not require `repository.owner.login` at all [3](#0-2) . A payload can therefore include `repository: {full_name: "victim-org/victim-repo"}` (no `owner` key) plus `organization: {login: "attacker-org"}`. `repository_owner` resolves to `"attacker-org"`; if `attacker-org`'s `GitHubApp` config has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally regardless of the actual `X-Hub-Signature` sent [9](#0-8) . The request passes verification, `LabelCapturingHandler.call(params)` runs, resolves the *victim's* repository/stack via `repository.full_name`, and overwrites that `PullRequest`'s `labels` attribute — which subsequently becomes uppercased environment keys via `ReviewStack#env` (not directly inspected here, but referenced by the question and consistent with how `PullRequest#labels` is documented to feed environment variables in `README.md`).

None of the existing guards stop this: `check_if_ping` and `drop_unhandled_event` only gate on the `X-Github-Event` header [10](#0-9) ; `verify_signature` explicitly implements the vulnerable fallback; the `ExplicitParameters` schema in the handler validates `repository.full_name` presence but never cross-checks it against `repository.owner.login` or `organization.login`.

### Impact Explanation
An attacker who registers/controls a GitHub organization onboarded to the same Shipit instance without a configured `webhook_secret` (a legitimate but weakly-configured tenant, e.g. a low-security internal org) can forge signed-looking webhook requests that mutate `PullRequest` records — and by extension review-stack environment variables — belonging to any other repository/org configured on the same Shipit instance, as long as they know or guess that repo's `full_name`. This matches the "payload for one repository mutating another's stack/commit/task" Critical category, since it is a cross-tenant write achieved without possessing the victim org's `webhook_secret`.

### Likelihood Explanation
Exploitation requires: (1) an organization onboarded on the target Shipit instance configured with no `webhook_secret` (this is an operator/config precondition, not guaranteed in all deployments — Shipit's setup docs recommend always configuring a `webhook_secret`, but the code path does not enforce this), and (2) knowledge of the victim `repository.full_name` and an existing review-stack pull request for that repo/branch. Given those, the attacker only needs to send one crafted unauthenticated HTTP POST; no GitHub account interaction with the victim repo is required. If no org on the instance has a blank `webhook_secret`, this specific bypass is not exploitable, though the underlying identity-divergence bug (verification key vs. write key mismatch) remains latent.

### Recommendation
In `WebhooksController#verify_signature`/`repository_owner`, derive the verification identity from the exact same field the handlers use to select the repository (`repository.full_name`'s owner segment), and reject requests where `repository.owner.login` is absent while `repository.full_name` is present. Additionally, `GitHubApp#verify_webhook_signature` should not silently return `true` for organizations lacking a configured `webhook_secret`; either require `webhook_secret` for every registered organization or reject unsigned/blank-secret webhook events outright. Finally, handlers should validate that the org implied by the verified `repository_owner` matches the org portion of `params.repository.full_name` before acting.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub):
1. Configure two orgs in `Shipit.github_apps`/secrets: `"attacker-org"` with `webhook_secret: nil`, and `"victim-org"` with a real `webhook_secret`.
2. Create a `Shipit::Repository` for `"victim-org/victim-repo"` with an active review stack and an existing `Shipit::PullRequest` with `labels: []`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, an arbitrary/garbage `X-Hub-Signature`, and JSON body:
   ```json
   {
     "action": "labeled",
     "number": <pr number>,
     "pull_request": { ...valid pull_request with labels: [{"name":"PROD"}]... , "head": {...}},
     "repository": { "full_name": "victim-org/victim-repo" },
     "organization": { "login": "attacker-org" },
     "sender": { "login": "attacker" }
   }
   ```
4. Assert response is `200 OK` (not `422`), i.e. `repository_owner` resolved to `"attacker-org"` (`params.dig('repository','owner','login')` nil, fallback to `"attacker-org"`) and `Shipit.github(organization: "attacker-org").verify_webhook_signature` returned `true` despite a bogus signature — proving `repository_owner ("attacker-org") != actual owner of repository.full_name ("victim-org")`.
5. Reload the victim `PullRequest` and assert `labels == ["PROD"]`, proving the attacker-verified request mutated a record owned by `"victim-org"`, which never validated the request.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
          end
```
