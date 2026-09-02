### Title
Signature-verifying org diverges from Repository-resolving org, letting a no-secret org forge webhooks that archive/unarchive a victim repo's review stack via `UnlabeledHandler` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/webhook config to verify a signature against using `repository_owner` (`params.dig('repository','owner','login')`), while every `pull_request` handler (including `UnlabeledHandler`) resolves the actual `Shipit::Repository` record to mutate using `params.repository.full_name` (`app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb:60-63`). These two values are never checked for consistency, so in a multi-org GitHub App configuration an attacker who names an org with no configured `webhook_secret` in `repository.owner.login`, while pointing `repository.full_name` at a different, victim-owned repository, gets a signature check that trivially passes and a state mutation performed against the victim's repository/stack.

### Finding Description
The invariant that should hold is:
`org_used_to_verify(payload) == org_that_owns(Repository resolved from payload)`.

Concretely: `repository_owner = params.dig('repository','owner','login')` (`app/controllers/shipit/webhooks_controller.rb:59-62`) should equal the owner segment of `params.repository.full_name`, since that same payload is later used by `UnlabeledHandler#repository` to do `Shipit::Repository.from_github_repo_name(params.repository.full_name)` (`app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb:59-63`, and `app/models/shipit/repository.rb:53-56`, which just splits `full_name` on `/` and does a DB lookup, with no cross-check against `repository.owner.login`).

Trace:
1. `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` (`app/controllers/shipit/webhooks_controller.rb:25`).
2. In multi-org mode (`github_default_organization` non-nil), `Shipit.github` looks up `github_app_config(organization)` keyed strictly by the attacker-supplied `repository_owner` string (`lib/shipit.rb:170-181`, `196-200`). If that org key doesn't exist, `GithubOrganizationUnknown` is raised and the request is rejected (422) — so the attacker must name an org that *is* configured.
3. `GitHubApp#verify_webhook_signature` has `return true unless webhook_secret` (`lib/shipit/github_app.rb:76-77`). If the chosen org's config has no `webhook_secret` set, **any signature (or none) is accepted**.
4. The controller never re-derives or checks the org against `params.repository.full_name`; it dispatches the whole payload to handlers regardless (`app/controllers/shipit/webhooks_controller.rb:10-15`).
5. `UnlabeledHandler#repository` resolves the real target `Shipit::Repository` purely from `params.repository.full_name` (`app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb:59-63`), independent of whichever org authenticated the request.
6. `UnlabeledHandler#handle` then calls `stack.archive!`/`stack.unarchive!` on `ReviewStackAdapter`, which looks the `ReviewStack` up by `environment: "pr#{params.number}"` scoped to that resolved repository's `review_stacks` (`app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:15-16`, `96-98`), and calls `stack.archive!(user, ...)` / `stack.unarchive!(...)` (lines 23-50), mutating a real record belonging to the victim's repository.

The attacker's forged request: `X-Github-Event: pull_request`, body `{"action":"unlabeled","number":<victim PR number>,"pull_request":{...,"state":"open","labels":[...]},"repository":{"owner":{"login":"no-secret-org"},"full_name":"victim-org/victim-repo"},"sender":{"login":"attacker"}}`, with any/garbage `X-Hub-Signature` (or omitted, since the check is skipped). No knowledge of `victim-org`'s webhook secret, session, or API token is required — only that `no-secret-org` is a configured Shipit GitHub org lacking a `webhook_secret`, and that the attacker knows/guesses an existing review-stack PR number for the victim repository.

Existing guards do not stop this: `drop_unhandled_event` only checks the event type is handled; `verify_signature` only fails on totally unknown orgs (`GithubOrganizationUnknown`) or on a bad signature *when a secret is configured for the chosen org*; the `ExplicitParameters` schema in `UnlabeledHandler` only validates shapes/types, not that `repository.owner.login == full_name`'s owner segment; and `Repository.from_github_repo_name` performs no cross-check either.

Regarding the "shared commit SHA" / bare-SHA status lookup part of the question: `UnlabeledHandler` and `ReviewStackAdapter` do not perform any commit lookup by SHA — the stack is located purely by `environment: "pr#{number}"` scoped to the resolved repository (`review_stack_adapter.rb:15-16`, `96-98`). The `head.sha` field is required by the params schema but unused for lookup, so the "shared commit SHA collision" mechanism described in the question does not apply to this handler; the actual and sufficient exploit path is the owner/full_name divergence in signature verification described above.

### Impact Explanation
An attacker with no Shipit credentials can force `stack.archive!` or `stack.unarchive!` on an arbitrary victim repository's review stack (`app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb:49-57`, `review_stack_adapter.rb:23-50`), which per `ReviewStackAdapter#archive!`/`#unarchive!` also calls `stack.remove_from_provisioning_queue`, `stack.deprovision`, or re-queues it for provisioning (`review_stack_adapter.rb:32-34`, `46-48`). This is a payload from one (attacker-named, low-config) org mutating another org's stack — a cross-tenant state-manipulation write, matching the Critical category "a payload for one repository mutating another's stack." It is repeatable against any repository/PR combination as long as the attacker can enumerate/guess PR numbers with existing review stacks, and is not limited to a single victim.

### Likelihood Explanation
This requires the Shipit deployment to be running in **multi-org GitHub App configuration** (i.e., `secrets.github` keyed by organization, so `github_default_organization` is non-nil — see `lib/shipit.rb:183-188`, `196-200`) **and** at least one configured org lacking a `webhook_secret` value. This is a real, supported configuration shape (see `test/dummy/config/secrets_double_github_app.yml`), not a hypothetical one — Shipit explicitly supports per-org webhook secrets, and nothing enforces that every configured org must have a secret. Given that precondition, attacker cost is trivial: a single unauthenticated HTTP POST with a hand-crafted JSON body, no signature computation needed. Repeatable at will.

### Recommendation
Verify the webhook signature using the same org/repository identity that will actually be mutated. Concretely:
1. In `Shipit::WebhooksController#verify_signature`, after resolving `repository_owner`, also derive the owner segment from `params.dig('repository','full_name')` and reject (422) if they don't match (case-insensitively).
2. Alternatively/additionally, require `webhook_secret` to be present for every configured org (fail closed instead of `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature`), removing the "no-secret org" bypass entirely.
3. Defense in depth: have `Shipit::Repository.from_github_repo_name` / handler base class assert `repository.owner == repository_owner` (the org actually used to authenticate) before allowing any state-mutating handler to run.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb`, no live GitHub):
1. Seed `Rails.application.credentials`/test secrets with a multi-org github config: org `"no-secret-org"` with no `webhook_secret`, and org `"victim-org"` with a real `webhook_secret`.
2. Create `victim_repo = Repository.create!(owner: "victim-org", name: "victim-repo", provisioning_behavior: "allow_with_label", review_stacks_enabled: true)` and an existing, non-archived `ReviewStack` under it with `environment: "pr42"`.
3. Assert precondition (equality that should hold but doesn't): `assert_equal "victim-org", repository_owner_would_resolve_to` vs actual `repository_owner_used_for_signature = "no-secret-org"` — i.e. explicitly assert these two differ in the crafted payload.
4. POST to `/webhooks` with header `X-Github-Event: pull_request`, no/garbage `X-Hub-Signature`, and JSON body: `action: "unlabeled"`, `number: 42`, `pull_request.state: "open"`, `pull_request.labels: []` (no provisioning label so `unarchive?`/`archive?` fires per behavior), `repository.owner.login: "no-secret-org"`, `repository.full_name: "victim-org/victim-repo"`, `sender.login: "attacker"`.
5. Assert response is `200 OK` (not `422`).
6. Reload the seeded `ReviewStack` and assert its `archived?`/state changed as `UnlabeledHandler` dictates (e.g. `assert stack.reload.archived?` or `assert_not stack.reload.archived?` matching the configured `provisioning_behavior`), proving a payload "authenticated" via `no-secret-org` mutated `victim-org`'s stack. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L41-63)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-50)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end

          def find_or_create!
            stack || create!
          end

          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```
