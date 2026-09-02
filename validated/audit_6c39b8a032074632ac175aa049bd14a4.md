Now I have sufficient evidence to confirm and detail the vulnerability.

### Title
Webhook signature scoped to `repository.owner.login` while target repository/stack is resolved from unrelated `repository.full_name`, allowing a no-secret org to forge events onto any other repo's review stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the `webhook_secret`) using `params.dig('repository','owner','login')`, but `LabelCapturingHandler` (and its sibling `pull_request` handlers) resolve the actual `Repository`/`ReviewStack` using the independent `params.repository.full_name` field, with no check that the two agree. Because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org's `webhook_secret` is blank, an attacker who knows of any Shipit-configured GitHub organization without a `webhook_secret` can forge a `pull_request` `labeled` event whose `repository.full_name` points at an arbitrary victim repo/stack.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:

`org_used_for_signature_verification (params.repository.owner.login)` **should equal** `org_that_owns_the_repository_actually_mutated (params.repository.full_name.split('/').first)` — for every accepted webhook. This engine allows the two to diverge.

Trace:
1. `Shipit::WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
2. `GitHubApp#verify_webhook_signature` returns `true` immediately if that org's `webhook_secret` is blank: `return true unless webhook_secret`. [3](#0-2) 
3. Once verification passes, the raw, attacker-controlled JSON is dispatched unchanged to all handlers for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [4](#0-3) 
4. `LabelCapturingHandler#repository` resolves the target repository purely from `params.repository.full_name`, a field that was never checked against `params.repository.owner.login`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. [5](#0-4) 
5. `review_stack`/`stack` then look up the `ReviewStack` scoped to that (attacker-chosen) `repository`, and `capture_labels` persists attacker-supplied label names onto that stack's `PullRequest`: `pull_request.update!(labels: params.pull_request.labels.map(&:name))`. [6](#0-5) 
6. `ReviewStack#env` folds those attacker-chosen (uppercased) label names directly into the stack's environment hash, which subsequently reaches command execution during provisioning/deploy: `.merge(pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" })`. [7](#0-6) 
7. If `review_stacks_enabled` and `allow_all` provisioning is configured on the victim repository, a first `opened` event (also unauthenticated for the same reason) auto-creates the review stack via `ReviewStackAdapter#create!`, which pulls `branch: params.pull_request.head.ref` straight from the forged payload and queues it for provisioning (`Shipit::ReviewStackProvisioningQueue.add(stack)`), i.e. it will check out attacker-controlled refs and execute `shipit.yml`. [8](#0-7) 

Root cause: the verification step and the data-processing step consult two different, unrelated JSON fields (`repository.owner.login` vs `repository.full_name`) with no cross-validation, so authenticating as "org A" (misconfigured with no secret) authorizes mutation of any repository named in `full_name`, including ones under organizations that *do* have a properly configured secret.

Precondition: at least one GitHub organization must be registered in Shipit's multi-org `secrets.github` map with a blank `webhook_secret` (a supported, documented configuration per `docs/setup.md` "Using Multiple Github Applications"). This is a real, supported configuration shape, not a hypothetical.

Existing guards do not catch this: `drop_unhandled_event` only checks the event type exists a handler; `ExplicitParameters` (`params do ... end`) only enforces field types/presence, not cross-field relationships; there is no model validation tying `repository.owner.login` to `repository.full_name` at the webhook layer.

### Impact Explanation
An attacker who merely knows (or brute-forces/guesses) the name of any Shipit-registered organization lacking a `webhook_secret` can forge `pull_request` webhooks that write to *any other repository's* review-stack `PullRequest` record and, when combined with `review_stacks_enabled`/`allow_all`, cause creation and provisioning of a review stack for an attacker-chosen branch — which executes the victim repository's `shipit.yml` commands under Shipit's environment (including whatever secrets/`GITHUB_TOKEN` the provisioner injects) with attacker-influenced environment variables (uppercased label names via `ReviewStack#env`). This is a payload for one repository (the no-secret org) mutating another repository's stack — matching the Critical class ("a payload for one repository mutating another's stack"). It is fully repeatable against any repository resolvable by `Repository.from_github_repo_name`, regardless of that repository's own tenant/org configuration.

### Likelihood Explanation
Requires: (a) at least one Shipit-configured GitHub org with `webhook_secret` unset — a documented, plausible operational lapse in multi-org deployments; (b) a target repository with `review_stacks_enabled` and `allow_all` provisioning; (c) no authentication of any kind beyond crafting a JSON POST to `/webhooks` with the correct `X-Github-Event: pull_request` header. Attacker cost is a single unauthenticated HTTP POST; no GitHub account interaction with the victim repo is required at all, since the entire payload is attacker-fabricated.

### Recommendation
Bind webhook authentication to the same repository the handlers act on: verify the signature using the GitHub App config resolved from the *same* `repository.full_name`/owner used later by handlers (i.e., derive `repository_owner` from the persisted `Shipit::Repository` record matched by `full_name`, or otherwise assert `params.repository.owner.login.downcase == params.repository.full_name.downcase.split('/').first`). Additionally, `GitHubApp#verify_webhook_signature` returning `true` for organizations with blank secrets should be reconsidered/require an explicit opt-in flag, since a misconfigured or transitional org effectively disables webhook integrity for whatever `full_name` an attacker supplies in the payload.

### Proof of Concept
Minitest plan under `test/controllers/shipit/webhooks_controller_test.rb` (or a new test file), no live GitHub:
1. Configure `Shipit.stubs(:secrets)` (or use `test/dummy/config/secrets_double_github_app.yml`-style fixture) with two orgs: `NoSecretOrg` (no `webhook_secret`) and implicitly the victim repo's owner `VictimOrg` (repository records use plain `owner`/`name` columns, not tied to the multi-org github config, so no secret is even required on `VictimOrg` for the DB lookup).
2. Create `repository = shipit_repositories(:shipit)` (or a factory) with `review_stacks_enabled: true`, `provisioning_behavior: 'allow_all'`, owner/name matching a "victim/repo" full_name.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no/garbage `X-Hub-Signature`, and JSON body: `{"action": "labeled", "number": 1, "pull_request": {..., "labels": [{"name": "malicious_env"}], "head": {"ref": "evil-branch", ...}}, "repository": {"owner": {"login": "NoSecretOrg"}, "full_name": "victim/repo"}, "sender": {"login": "attacker"}}`.
4. Assert response is `200 OK` (not `422`), proving `verify_signature` passed using `NoSecretOrg`'s blank secret.
5. Assert `repository.review_stacks.find_by(environment: "pr1").pull_request.labels == ["malicious_env"]`, proving the victim's stack (owned by a different, unrelated org/full_name) was mutated by a request authenticated against `NoSecretOrg`.
6. Assert `ReviewStack#env["MALICIOUS_ENV"] == "true"` on the victim stack, demonstrating the attacker-controlled environment injection that would reach `Command`/`PTY.spawn` during provisioning.

Binding checked before/after: `params.repository.owner.login` ("NoSecretOrg") != `params.repository.full_name.split('/').first` ("victim") both before and after the request — the divergence is never rejected, confirming the vulnerability.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
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
