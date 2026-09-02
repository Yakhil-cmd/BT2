### Title
Webhook signature is verified against `repository.owner.login` while the actor mutated is resolved from `repository.full_name`, letting a no-secret organization's webhook authenticate a `pull_request`/`reopened` event that mutates any other repository's review stack - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a webhook using `Shipit.github(organization: repository_owner)` where `repository_owner` is read from `params.dig('repository','owner','login')`, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization has no `webhook_secret` configured. All `pull_request` handlers (`ReopenedHandler`, `LabelCapturingHandler`, etc.) instead resolve the actually-mutated repository/stack from the independent field `params.repository.full_name`. Because these two attacker-controlled fields are never cross-validated, a forged body naming a no-secret organization in `repository.owner.login` but a different, unrelated repository in `repository.full_name` passes signature verification while mutating that other repository's stack.

### Finding Description
The broken binding: the code implicitly assumes `params.repository.owner.login == owner_of(params.repository.full_name)`, but nothing enforces this equality.

- `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30, 59-62) computes `repository_owner` from `params.dig('repository','owner','login')` and calls `github_app.verify_webhook_signature(header, raw_post)`.
- `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83) does `return true unless webhook_secret` — if the organization named in `repository.owner.login` has no configured `webhook_secret`, the request is accepted with **no signature check at all**, and even when a secret exists, only the legacy `sha1=` scheme is accepted (`return false unless algorithm == 'sha1'`).
- Once past `verify_signature`, `Shipit::Webhooks.for_event('pull_request')` dispatches to handlers such as `ReopenedHandler` and `LabelCapturingHandler` (app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb:49-53, label_capturing_handler.rb:110-118), which resolve the target repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a completely separate JSON field from the one used for authentication.
- `LabelCapturingHandler#capture_labels` (label_capturing_handler.rb:98-102) persists `params.pull_request.labels.map(&:name)` onto `stack.pull_request`, and `ReviewStack#env` (app/models/shipit/review_stack.rb:84-93) later upcases every stored label name into a `"NAME" => "true"` environment variable merged into the stack's deploy/task environment.

Exploit flow: an attacker crafts a `pull_request`/`action=reopened` JSON body with `repository.owner.login` set to any Shipit-configured organization that has no `webhook_secret` set (or one they otherwise know), sends `X-Hub-Signature: sha1=<anything>` (or omits any secret-dependent correctness since verification is skipped entirely), but sets `repository.full_name` to the victim's real `owner/repo`. `verify_signature` authenticates the request against the harmless no-secret organization and passes; `ReopenedHandler`/`LabelCapturingHandler` then resolve and mutate the victim repository's `ReviewStack`/`PullRequest`, unarchiving it and overwriting its labels with attacker-chosen strings, which flow into `ReviewStack#env` as arbitrary environment variables.

Existing guards do not close this gap: `drop_unhandled_event` only checks the event type exists; the `ExplicitParameters` schema (`params do ... end`) only validates types/shapes, not cross-field consistency between `repository.owner.login` and `repository.full_name`; and `verify_signature`'s org lookup uses a field that is never reconciled with the field the handlers actually act on.

### Impact Explanation
An attacker who controls no Shipit secret can cause a `PullRequest`/`ReviewStack` record belonging to a repository they do not control to be mutated (labels overwritten, stack unarchived) purely by naming a different, no-secret-configured organization in the payload's `repository.owner.login`. This is a payload authenticated for one repository/organization mutating another's stack/record — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Repeatable against any target repository whose `owner/repo` string the attacker can guess, for every Shipit instance operating at least one organization without a configured `webhook_secret`. The forged labels becoming uppercase environment variables in `ReviewStack#env` further extends the blast radius into whatever commands/tasks read that environment on the victim's review stack.

### Likelihood Explanation
Requires: (1) the Shipit deployment has at least one GitHub organization configured with no `webhook_secret` (a real, plausible misconfiguration, not requiring any secret knowledge by the attacker); (2) the attacker can reach `POST /webhooks` unauthenticated, which is by design; (3) the attacker knows or guesses the victim's `owner/repo` full name, which is public information. No GitHub-side interaction or real webhook delivery is required since the endpoint is unauthenticated HTTP. Cost is a single crafted HTTP request, fully repeatable.

### Recommendation
Cross-validate that `params.repository.owner.login` matches the owner segment of `params.repository.full_name` before dispatching to any handler, and reject the request (422) on mismatch. Additionally, treat a missing `webhook_secret` as a configuration error that refuses all unsigned webhooks rather than implicitly trusting them (`return true unless webhook_secret` should instead reject or require an explicitly-opted-in "no verification" flag), and support/require `X-Hub-Signature-256` (sha256) verification.

### Proof of Concept
minitest plan (extend `test/controllers/webhooks_controller_test.rb`):
```ruby
test "pull_request reopened forged with mismatched owner/full_name mutates a different repository's stack" do
  # Precondition: organization "no-secret-org" configured with no webhook_secret in test config
  victim_stack = shipit_stacks(:review_stack) # continuous_deployment-enabled review stack for "shopify/shipit"
  victim_stack.pull_request.update!(labels: [])

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' # not a valid HMAC for anything

  body = {
    action: 'reopened',
    number: victim_stack.pull_request.number,
    pull_request: {
      id: 1, number: victim_stack.pull_request.number, url: 'x', title: 't', state: 'open',
      additions: 0, deletions: 0,
      head: { sha: 'a' * 40, ref: victim_stack.branch },
      user: { login: 'attacker' },
      assignees: [],
      labels: [{ name: 'INJECTED_ENV' }]
    },
    repository: {
      full_name: victim_stack.repository.github_repo_name, # "shopify/shipit" (the victim)
      owner: { login: 'no-secret-org' }                     # authenticates against an org with no secret
    },
    sender: { login: 'attacker' }
  }.to_json

  post :create, body:, as: :json

  assert_response :ok
  assert_equal ['INJECTED_ENV'], victim_stack.pull_request.reload.labels
  assert_equal 'true', victim_stack.reload.env['INJECTED_ENV']
end
```
Assert on both sides of the broken equality: `params.dig('repository','owner','login')` ("no-secret-org", used for auth) != owner segment of `params.dig('repository','full_name')` ("shopify", the actually mutated repo) — showing the request is authenticated as one entity but mutates another. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L94-118)
```ruby
          def pull_request
            params.pull_request
          end

          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```
