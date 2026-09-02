### Title
Signature-verifying org and mutated-repo org can diverge, letting an attacker-authenticated webhook edit another org's `PullRequest` - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/webhook secret to validate the HMAC using `repository.owner.login`, while `EditedHandler` (and its siblings) resolves the target `Repository`/`Stack`/`PullRequest` using the independent `repository.full_name` field. Because these two fields are never cross-checked, an attacker who controls a GitHub org/repo with no `webhook_secret` configured in `Shipit.github_teams` can forge a payload whose `owner.login` names that unsecured org (causing signature verification to pass trivially) while `full_name` names an arbitrary victim org/repo, letting the handler mutate that victim's `PullRequest` record.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't: `repository_owner` (the org used to select the webhook secret in `verify_signature`) should equal `Shipit::Repository.from_github_repo_name(params.repository.full_name).owner` (the org whose data the handler mutates). Concretely:

- `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` and `repository_owner` is defined purely as `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that organization: `return true unless webhook_secret` [3](#0-2) .
- `EditedHandler#repository` resolves the repository to operate on strictly from `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name`, which is a completely separate field from `repository.owner.login` and is never validated against it [4](#0-3) .
- `EditedHandler#process` then looks up the persisted `PullRequest` by `number` joined through `stack: :repository` scoped to that resolved repository's `id`, and calls `pull_request.update(github_pull_request: params.pull_request)` unconditionally if found [5](#0-4) .

Exploit flow: attacker crafts a `pull_request` event with `action: "edited"`, sets `repository.owner.login` to an org for which no `webhook_secret` is configured in the deployment's `Shipit.github_teams`/GitHub App config (any org for which the operator hasn't set up a secret — including an org the attacker themselves administers, or simply omits/misconfigures), and sets `repository.full_name` to `victim-org/victim-repo` (a real, secret-protected org tracked by Shipit). Because `verify_webhook_signature` short-circuits to `true` for the org with no secret, `verify_signature` passes with zero cryptographic proof of authenticity. `drop_unhandled_event` and the `ExplicitParameters` schema (`EditedHandler.params`) only require `repository.full_name` to be present as a `String`; they impose no relationship to `repository.owner.login` [6](#0-5) . The handler then resolves the real victim `Repository` by `full_name`, finds the victim's `PullRequest` by `number`, and overwrites its persisted `github_pull_request` state with entirely attacker-supplied JSON.

Existing guards do not close this gap: `verify_signature`'s only failure mode tied to organization mismatch is `GithubOrganizationUnknown`, which is raised only when the organization named in `repository.owner.login` is not configured/known to Shipit at all — not when it is a known-but-secretless organization, and not when it differs from the org implied by `full_name` [7](#0-6) . Nothing in `Repository#from_github_repo_name`, the `Repository` model validations, or the `EditedHandler` schema cross-checks the owner used for authentication against the owner implied by `full_name` [8](#0-7) .

### Impact Explanation
A payload authenticated under one (unprotected) organization's identity can mutate persisted state (`Shipit::PullRequest#github_pull_request`) belonging to a completely different, secured organization's stack. On a stack marked as a production environment, this is a payload for one repository mutating another repository's/stack's `PullRequest` record — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Any organization onboarded to Shipit without a configured `webhook_secret` (or any org the attacker fully controls, if it happens to be a tracked org with no secret) becomes a springboard to inject fabricated pull-request metadata (title, state, additions/deletions, head sha/ref, assignees, labels, sender) into any other tracked repository's pull requests by number, repeatably, with only knowledge of the target's `number` and `full_name` — both discoverable publicly on GitHub.

### Likelihood Explanation
Preconditions: (1) the Shipit deployment must have at least one organization registered without a `webhook_secret` (a plausible, common misconfiguration/legacy-org scenario, or an org the attacker controls if it happens to be tracked), and (2) the victim stack/repository must be a different, tracked organization with an existing `PullRequest` record for the guessed/known `number`. Attacker cost is a single unauthenticated `POST /webhooks` request with a crafted JSON body and `X-Github-Event: pull_request` header — no signature computation needed since verification is bypassed for the secretless org. This is fully repeatable against any `number` on the victim stack.

### Recommendation
In `WebhooksController`, after verifying the signature, cross-validate that the organization used to authenticate (`repository_owner`) matches the owner implied by `params.dig('repository', 'full_name')` before dispatching to handlers; reject the request (422) on mismatch. Additionally, treat organizations with no configured `webhook_secret` as unable to authenticate at all (fail closed) rather than defaulting `verify_webhook_signature` to `true`, or require every tracked organization to have a secret configured.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Fixture setup: a victim stack/repository `victim-org/victim-repo` (tracked, e.g. `shipit_stacks(:shipit)` with `environment: "production"`) with a persisted `Shipit::PullRequest` (`number: 42`, some baseline `github_pull_request` state) belonging to it.
2. Configure/stub `Shipit.github_teams` (or stub `Shipit.github`) so that organization `no-secret-org` has no `webhook_secret`, causing `Shipit.github(organization: 'no-secret-org').verify_webhook_signature` to return `true` unconditionally (exercise the real `return true unless webhook_secret` branch, not a mock).
3. Build payload: `{ action: 'edited', number: 42, pull_request: { ...attacker-controlled title/state/head/assignees/labels... }, repository: { owner: { login: 'no-secret-org' }, full_name: 'victim-org/victim-repo' }, sender: { login: 'attacker' } }`.
4. `post :create` with `X-Github-Event: pull_request`, no valid `X-Hub-Signature` for `victim-org`'s secret (send garbage or omit it).
5. Assert response is `:ok` (i.e., signature check passed despite invalid signature for the victim org).
6. Reload the fixture `PullRequest` and assert `pull_request.github_pull_request['title']` (and other fields) now equal the attacker-supplied values — proving the equality `repository_owner == owner(full_name)` was violated and the victim's persisted record was mutated by a request that never authenticated against the victim org's secret. [9](#0-8) [3](#0-2) [10](#0-9)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-65)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
