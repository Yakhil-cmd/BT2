This confirms the finding: `verify_signature` in `WebhooksController` selects the org-specific `GitHubApp` (and thus HMAC secret) using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` from the same untrusted JSON body being verified [1](#0-0) [2](#0-1) . Once the signature validates against OrgReal's `webhook_secret`, the raw parsed body is dispatched unmodified to every registered handler [3](#0-2) . `ClosedHandler#repository` then independently reads `params.repository.full_name` — a different field of the same body — to resolve the `Shipit::Repository` and its `review_stacks`, with no re-check that this field matches the org used in `verify_signature` [4](#0-3) . `review_stack.archive!` is then called unconditionally when `action == "closed"` [5](#0-4) .

### Title
Webhook authenticates via `repository.owner.login` but mutates the repository named in `repository.full_name`, allowing cross-org review stack archival - (File: app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb)

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate against using `params.dig('repository','owner','login')`, but `ClosedHandler` acts on `params.repository.full_name`. Since both fields live in the same attacker-controlled JSON body and are never cross-checked, an attacker who owns a repo under OrgReal can forge a `pull_request.closed` payload that is validated with OrgReal's own webhook secret while `repository.full_name` is set to an OrgVictim repository, causing `review_stack.archive!` to run against OrgVictim's review stack.

### Finding Description
The broken binding: authentication org (`repository_owner` = `params.dig('repository','owner','login')` used in `Shipit.github(organization: repository_owner)` and `verify_webhook_signature`) is assumed to equal the org whose data is mutated (derived from `params.repository.full_name` in `ClosedHandler#repository`, feeding `Shipit::Repository.from_github_repo_name`). These are two independently attacker-writable strings in the same JSON body, and nothing enforces `repository.full_name.split('/').first == repository.owner.login`.

Exploit flow:
1. Attacker owns `OrgReal/some-repo` with a correctly configured `webhook_secret` for OrgReal, so they can compute a valid `X-Hub-Signature` for any body using that secret (they control the repo, so they can configure the secret, or in a variant, guess/reuse a secret they legitimately possess for their own org).
2. Attacker crafts a `pull_request` `closed` JSON body where `repository.owner.login = "OrgReal"` and `repository.full_name = "OrgVictim/other-repo"` (a real review-stack-enabled repo belonging to OrgVictim), and picks arbitrary `pull_request.number`/`head.sha`.
3. POSTs to `/webhooks` with `X-Hub-Signature` computed using OrgReal's secret over the raw body.
4. `verify_signature` calls `Shipit.github(organization: 'OrgReal')`, verifies successfully because the attacker signed with OrgReal's secret [1](#0-0) .
5. `create` dispatches the parsed body to `Shipit::Webhooks.for_event('pull_request')`, invoking `ClosedHandler` [3](#0-2) .
6. `ClosedHandler#repository` resolves `Shipit::Repository.from_github_repo_name('OrgVictim/other-repo')`, and `process` calls `review_stack.archive!`, archiving OrgVictim's real review stack [6](#0-5) .

No existing guard prevents this: `verify_signature` never inspects `full_name`, and the `ExplicitParameters` schema in `ClosedHandler.params` only requires `repository.full_name` to be a `String` — it performs no cross-field validation against the owner used for signing [7](#0-6) .

### Impact Explanation
An attacker who legitimately controls any repository (and its webhook secret) under some GitHub organization can archive (undeploy/tear down) the review-stack environment of an arbitrary repository belonging to a different, victim organization, provided that org/repo has review stacks enabled. This is unauthorized state mutation across tenant boundaries — a payload authenticated for one org's repository mutates another org's stack — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The action is repeatable for any PR number/head sha the attacker chooses, against any repository name they can guess, without any interaction from OrgVictim.

### Likelihood Explanation
Preconditions: attacker must own/administer at least one repository under some org configured in Shipit with a webhook and its own `webhook_secret` (a very low bar — it only requires normal onboarding as documented, not special privilege), and know/guess the victim's `owner/repo` full name (public information). No Shipit session, API token, or GitHub App secret is needed for the victim's org. The forged request is a single HTTP POST with a correctly computed HMAC using a secret the attacker legitimately possesses for their own org. This is highly feasible and fully repeatable.

### Recommendation
In `WebhooksController#verify_signature`, or before dispatching to handlers, enforce that the organization used to select/verify the webhook secret matches the org portion of `params.dig('repository','full_name')` (and any other repository references embedded in the payload used by handlers), rejecting the webhook with 422 on mismatch. Alternatively, have handlers derive the operated-on organization exclusively from the same field validated during signature verification, and reject events where `repository.full_name`'s owner segment differs from `repository.owner.login`.

### Proof of Concept
minitest plan (extends `test/controllers/webhooks_controller_test.rb` style):
1. Configure two orgs in `Shipit.github_apps`-like test config: `OrgReal` with `webhook_secret: 'real_secret'`, and `OrgVictim` with `webhook_secret: 'victim_secret'`.
2. Create `victim_repo = Shipit::Repository.create!(...)` under `OrgVictim/other-repo` with `review_stacks_enabled?` true, and an existing `Shipit::ReviewStack` for some PR number, stubbing/expecting `archive!` to be called.
3. Build JSON body: `{ action: 'closed', number: N, pull_request: {...}, repository: { full_name: 'OrgVictim/other-repo', owner: { login: 'OrgReal' } }, sender: { login: 'attacker' } }`.
4. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest('sha1', 'real_secret', body)`.
5. POST to `/webhooks` with header `X-Github-Event: pull_request` and the computed signature.
6. Assert response is `200 OK` (signature accepted) and assert `victim_repo.review_stacks.find_by(pull_request_number: N).archive!` was invoked (e.g., via mocking `ReviewStackAdapter`/`archive!` or asserting the stack's `stack.deleted?`/`archived_at` state changed), demonstrating equality `repository_owner ('OrgReal') != repository.full_name.split('/').first ('OrgVictim')` yet the mutation proceeds against OrgVictim.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```
