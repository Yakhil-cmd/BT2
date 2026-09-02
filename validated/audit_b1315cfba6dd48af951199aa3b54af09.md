### Title
`pull_request` webhook signature is verified against `repository.owner.login`'s org secret while the mutated resource is selected by `repository.full_name`, letting a no-secret org's "signature" authorize writes on any other repo's `PullRequest`/`ReviewStack` — `LabelCapturingHandler` (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` picks the HMAC secret to check using `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) , but `LabelCapturingHandler` resolves and mutates the actual repository/stack purely from `params.repository.full_name` [3](#0-2) , with no code anywhere checking that `full_name`'s owner segment equals the org whose secret authenticated the request. If that authenticating org has no `webhook_secret` configured, `GitHubApp#verify_webhook_signature` unconditionally returns `true` [4](#0-3) , letting an unprivileged attacker "authenticate" as a throwaway/no-secret org while their payload's `repository.full_name` targets a completely different, real victim stack.

### Finding Description
The broken binding, stated as an equality that the code implicitly assumes but never enforces:
`org(params.repository.owner.login) == org(params.repository.full_name)`

In reality these are two independently attacker-controlled JSON fields in the same unauthenticated POST body, and nothing ties them together.

Path:
1. `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)`, where `repository_owner` is `params.dig('repository','owner','login')` [2](#0-1) .
2. `Shipit.github` looks up that org's config and constructs a `GitHubApp` with that org's `webhook_secret` [5](#0-4) .
3. `GitHubApp#verify_webhook_signature` short-circuits to `true` if that org's `webhook_secret` is blank/nil: `return true unless webhook_secret` [4](#0-3) . The shipped example configs (`config/secrets.development.example.yml`, `test/dummy/config/secrets.yml`, `test/dummy/config/secrets_double_github_app.yml`) all leave `webhook_secret` commented as `# nil`, showing this is a normal, supported, documented configuration state, not an edge-case misconfiguration.
4. Once `verify_signature` passes, `WebhooksController#create` dispatches the whole parsed body — including the attacker-chosen `repository.full_name` — to every registered handler for the event [6](#0-5) .
5. `LabelCapturingHandler#repository` resolves the target `Shipit::Repository` solely via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [7](#0-6) , then locates the review stack by PR number via `ReviewStackAdapter#stack` (`scope.find_by(environment: "pr#{number}")`) [8](#0-7) , entirely independent of `repository_owner`.
6. For `action == "reopened"` with a present, unarchived stack, `capture_labels?` is true [9](#0-8) , and `capture_labels` persists `params.pull_request.labels.map(&:name)` onto `stack.pull_request` [10](#0-9) .
7. `ReviewStack#env` later uppercases each persisted label name into an environment key with value `"true"`, merged into the stack's env used by deploy/task/merge commands [11](#0-10) , confirmed by existing tests asserting `env["WIP"]`/`env["BUG"]` from labels [12](#0-11) .

The attacker's exact request: `POST /webhooks` with header `X-Github-Event: pull_request`, any `X-Hub-Signature` (or omitted), and JSON body where `repository.owner.login` = a configured org with no `webhook_secret` (e.g. one of the multiple orgs in a multi-tenant Shipit deployment), while `repository.full_name` = `"victim-org/victim-repo"` (a different, real, victim stack with `merge_queue_enabled: true`), `action: "reopened"`, `number` = an existing PR's number for an existing review stack, and `pull_request.labels` = attacker-chosen label objects.

Why existing guards fail: `drop_unhandled_event` only checks the event type is registered, not authenticity [13](#0-12) . `verify_signature`'s only failure mode besides bad signature is `GithubOrganizationUnknown` (raised only when the org name isn't present in config at all) [14](#0-13)  — it never raises or fails when the org is known but has no secret, and never cross-checks against `repository.full_name`. `ExplicitParameters` schema for the handler only validates types/presence of `repository.full_name`, not that it matches `repository.owner.login` [15](#0-14) . No model validation in `Repository`/`Stack`/`ReviewStack` enforces this either.

### Impact Explanation
An unprivileged attacker who can trigger any webhook delivery (or simply POST directly to `/webhooks` since there is no session/token requirement) can write attacker-chosen label strings onto a victim `PullRequest` belonging to a completely different, unrelated GitHub org's stack that they have no access to. Those strings become uppercased environment variable keys injected into every subsequent deploy/task/merge command executed for that stack (`ReviewStack#env`), which is a payload-for-one-repository-mutating-another's-stack primitive — matching the Critical category explicitly listed in scope ("a payload for one repository mutating another's stack, commit, task or team"). This is repeatable against any repository/stack in the Shipit instance as long as the attacker knows (or can enumerate/guess) an org name configured without a `webhook_secret`, and the effect (arbitrary attacker-controlled env-var injection into deploy-time environment) is directly consumed by shell-executed deploy/merge commands, materially raising risk of command injection or safety-check bypass in a stack the attacker never had any relationship with.

### Likelihood Explanation
Preconditions: (1) Shipit is configured with the multi-org `github:` schema (documented feature) and at least one configured org has no `webhook_secret` set — a state the project's own example/template configs ship with by default; (2) the victim stack/review-stack exists with a matching PR `number` and is not archived; (3) `merge_queue_enabled` is a stack-level toggle irrelevant to the write itself (it only affects downstream blast radius). Attacker cost is a single crafted HTTP POST with no authentication material and no need to know any real webhook secret. This is highly feasible and fully repeatable against any repo/stack in the deployment once the no-secret org is identified.

### Recommendation
Do not select the verification secret from the same untrusted payload field used to select the mutation target without cross-checking them. Concretely: after locating the org config, verify that the org derived from `params.repository.full_name` (i.e. the `owner` segment) equals `repository_owner`, rejecting the request otherwise. Additionally, treat a `webhook_secret`-less org config as "signature verification disabled for that org only" and refuse to let requests "authenticated" under that org select/mutate resources belonging to a different org's repository; alternatively, require `webhook_secret` to be present for any multi-org configuration entry (fail closed instead of `return true unless webhook_secret`).

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test, multi-org config)
test "pull_request reopened with owner/full_name org split writes labels onto a different org's stack" do
  Shipit.stubs(:secrets).returns(
    ActiveSupport::OrderedOptions.new.tap do |s|
      s.merge!(YAML.load_file('test/dummy/config/secrets_double_github_app.yml').deep_symbolize_keys)
      # simulate a real-world no-secret org left blank by an operator, as in the shipped example configs
      s[:github][:OrgOne][:webhook_secret] = nil
    end
  )

  victim_stack = shipit_stacks(:review_stack) # merge_queue_enabled: true, belongs to a *different* org/repo
  pr_number = victim_stack.pull_request.number

  payload = {
    action: "reopened",
    number: pr_number,
    pull_request: {
      id: 1, number: pr_number, url: "https://api.github.com/x", title: "x", state: "open",
      additions: 1, deletions: 1,
      head: { sha: "a" * 40, ref: "feature" },
      user: { login: "attacker" },
      assignees: [],
      labels: [{ name: "DISABLE_SAFETY" }]
    },
    # attacker-chosen no-secret org used only to pass signature check
    repository: { full_name: victim_stack.github_repo_name, owner: { login: "OrgOne" } },
    sender: { login: "attacker" }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # never validated because OrgOne has no secret

  post :create, body: payload, as: :json
  assert_response :ok

  # equality broken: request "authenticated" as OrgOne, but mutated a stack under a different owner/org
  assert_not_equal "OrgOne", victim_stack.reload.repository.owner
  assert_equal ["DISABLE_SAFETY"], victim_stack.pull_request.reload.labels
  assert_equal "true", victim_stack.reload.env["DISABLE_SAFETY"]
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/controllers/shipit/webhooks_controller.rb (L39-49)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L70-72)
```ruby
          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit.rb (L170-181)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-17)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
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

**File:** test/models/shipit/review_stack_test.rb (L59-65)
```ruby
    test "#env includes the stack's pull request labels" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
    end
```
