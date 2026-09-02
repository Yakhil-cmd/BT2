### Title
Webhook signature verification organization can diverge from the repository record mutated by the handler - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to check the signature based on `repository_owner`, which is parsed from `params.dig('repository','owner','login')`. The `PullRequest::OpenedHandler` (and `Handler#stacks`/`Repository.from_github_repo_name`) instead resolve the target `Repository` by splitting `params.repository.full_name` on `/`. Nothing in the code enforces that `repository.owner.login` matches the owner segment of `repository.full_name`, so an attacker who controls a repo (and its webhook secret) under their own org can sign a payload whose `full_name` names a different, victim-owned repository.

### Finding Description
The binding that must hold is: `organization_used_to_verify_signature == organization_owning_the_repository_record_the_handler_mutates`, i.e. `params.dig('repository','owner','login') == params.dig('repository','full_name').split('/').first`.

- `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` (or `organization.login` fallback) and picks the app/secret via `Shipit.github(organization: repository_owner)` [1](#0-0) [2](#0-1) .
- Once verified, `create` dispatches the raw parsed JSON to all handlers for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .
- `PullRequest::OpenedHandler#repository` independently resolves the target repository using only `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [4](#0-3) .
- `Repository.from_github_repo_name` simply splits the string on `/` and looks up by `owner`/`name` — it never reads `repository.owner.login` [5](#0-4) .
- The generic `Handler#stacks`/`repository_name` helper used by other handlers (push, status, check_suite, membership) has the same pattern: it reads `payload.dig('repository','full_name')` only [6](#0-5) .

Because these two derivations read different, independently attacker-controlled JSON fields (`repository.owner.login` vs `repository.full_name`), an attacker who owns `attacker-org/attacker-repo` (and thus can send a webhook signed with `attacker-org`'s configured `webhook_secret` from their GitHub org's webhook settings) can craft a raw POST body directly (bypassing GitHub's UI, since this is a raw HTTP POST to `/webhooks` with a manually computed `X-Hub-Signature`) where:
- `repository.owner.login` = `"attacker-org"` (so `verify_signature` picks `attacker-org`'s app/secret, and since the attacker knows and controls that secret, the HMAC signature validates), and
- `repository.full_name` = `"victim-org/victim-repo"` (a pre-existing, victim-tracked `Repository`/`Stack` in Shipit's DB).

The `OpenedHandler` then loads the real victim `Repository` row, and `ReviewStackAdapter#find_or_create!`/`create!` creates or looks up a `ReviewStack` scoped to that victim repository's `review_stacks`, using attacker-supplied `pull_request` data (branch name `params.pull_request.head.ref`, PR number, labels, sender login) [7](#0-6) . None of the existing guards (`drop_unhandled_event`, `ExplicitParameters` schema requiring only presence/type of `full_name` as a `String`, `Repository` format validators on `owner`/`name` columns) check consistency between `repository.owner.login` and `repository.full_name`.

### Impact Explanation
An attacker who controls only their own GitHub org/repo and its webhook secret can forge a signed webhook body that is verified using their own credentials, yet whose payload targets and mutates a different tenant's `Repository`/`ReviewStack` records (creating review stacks, attaching forged pull request metadata, or triggering archive/unarchive/label flows on other handlers that follow the same `payload.dig('repository','full_name')` pattern). This is a cross-tenant mutation caused by a payload for one repository (attacker's, used for signing) affecting another repository's (victim's) stack/PR records — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team" and effectively an authentication-bypass of the webhook provenance guarantee.

### Likelihood Explanation
Preconditions: Shipit must be configured with per-organization GitHub Apps/webhook secrets (multi-org setup, as supported by `Shipit.github(organization:)`) such that the attacker's own org has a distinct, attacker-controllable `webhook_secret`; the victim repository must already exist as a `Repository` row in Shipit (tracked stack/review-stacks). Given that, the attack requires only: sending a raw HTTP POST to `/webhooks` with header `X-Github-Event: pull_request`, a crafted JSON body with mismatched `repository.owner.login` vs `repository.full_name`, and `X-Hub-Signature` computed with the attacker's own known secret. No GitHub session, API token, or victim secret is needed — fully repeatable against any victim repository the attacker can guess/know the `owner/name` of.

Note: I was unable to fully verify within the available context whether `Shipit.github(organization:)` in `lib/shipit/github_app.rb` truly supports distinct per-organization secrets in all deployment configurations (single global app vs. one App per org) — this affects whether the attacker's org can have a genuinely different, attacker-known secret from the victim's. The engine's `test/dummy/config/secrets_double_github_app.yml` fixture name strongly suggests multi-org/multi-secret configurations are a supported and tested configuration, but I could not read `lib/shipit/github_app.rb` in this session to confirm the exact selection logic.

### Recommendation
Enforce a single, trusted source for the organization/repository identity used for both signature verification and record lookup. Concretely: after `verify_signature` succeeds, derive `repository_owner` and the repository/owner used by handlers from the *same* parsed value (e.g., pass `repository_owner` into handlers, or validate that `params.dig('repository','full_name').split('/').first.casecmp(repository_owner) == 0` before dispatching), rejecting the webhook (422) on mismatch. Apply the same consistency check inside `Handler#repository_name`/`Repository.from_github_repo_name` call sites so all handlers (not just `OpenedHandler`) are protected.

### Proof of Concept
Minitest (`test/controllers/webhooks_controller_test.rb`) outline:
1. Configure two orgs in `Shipit.github` config (or stub `Shipit.github(organization:)`) with distinct webhook secrets: `attacker-org` (attacker-known secret) and `victim-org` (victim/unknown secret).
2. Seed a `Shipit::Repository` for `victim-org/victim-repo` with `review_stacks_enabled: true` and `provisioning_behavior_allow_all: true`.
3. Build a `pull_request` "opened" JSON payload where `repository.owner.login == "attacker-org"` and `repository.full_name == "victim-org/victim-repo"`.
4. Compute `X-Hub-Signature` using the `attacker-org` secret (which the attacker is assumed to know) and POST it to `/webhooks` with `X-Github-Event: pull_request`.
5. Assert the response is `200 OK` (signature accepted) — proving `verify_signature` passed using the attacker's own org's secret.
6. Assert that `Shipit::ReviewStack.where(repository_id: victim_repository.id).count` increased by 1 (or, for the "no vulnerability" case, assert it stayed 0) — demonstrating the victim's repository record was mutated by a payload verified against the attacker's own credentials.

Given the code paths traced (`repository_owner` vs `Repository.from_github_repo_name(params.repository.full_name)`), the equality the binding requires does **not** hold in general, and no guard in the traced code enforces it — this is a valid finding, contingent on the multi-org/multi-secret configuration assumption noted above.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```
