### Title
Signature verification selects webhook secret by `organization.login`/`repository.owner.login` while all downstream handlers act on the independently-attacker-set `repository.full_name`, letting a webhook authenticated against one GitHub org's secret mutate another org's stack - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` picks the HMAC secret to validate a webhook against using `repository_owner`, computed as `params.dig('repository','owner','login') || params.dig('organization','login')`, while `LabelCapturingHandler` (and every other `pull_request` handler) resolves the target `Repository`/`Stack` purely from `params.repository.full_name` via `Repository.from_github_repo_name`. Because these are two independently attacker-controlled JSON paths, in a multi-organization Shipit deployment an attacker can authenticate the request against an org whose GitHub App has no `webhook_secret` configured while pointing `repository.full_name` at a completely different (victim) org's repository/stack.

### Finding Description
The broken binding: the code implicitly assumes
`repository_owner == owner_of(params.repository.full_name)`,
but nothing enforces this equality.

- `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`) is `params.dig('repository','owner','login') || params.dig('organization','login')`.
- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) fetches `Shipit.github(organization: repository_owner)` and checks the signature against *that* org's `webhook_secret`.
- `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) returns `true` unconditionally `unless webhook_secret` — i.e., if the org resolved by `repository_owner` has no secret configured, any signature (or none) passes.
- `Shipit.github` (`lib/shipit.rb:170-181`, `196-200`) supports per-organization app configs (documented multi-org setup in `docs/setup.md`), each with an independent `webhook_secret`, keyed by org login.
- Every `pull_request` handler, including `LabelCapturingHandler` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:110-113`), resolves the acted-upon repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a completely separate field from the one used to select the verifier.

Exploit flow: attacker crafts a `pull_request` `action=opened` payload where `repository` contains only `full_name: "VictimOrg/victim-repo"` (no `owner` sub-object, satisfying the handler's `requires :repository { requires :full_name }` schema without providing `owner.login`), and `organization.login = "LenientOrg"` — some other org configured in the same Shipit instance whose GitHub App has no `webhook_secret` set (a valid, documented configuration per `config/secrets.development.example.yml`/`docs/setup.md`). `repository_owner` falls back to `"LenientOrg"`, `verify_signature` passes unconditionally (no secret to check against), and the request is dispatched to handlers. `LabelCapturingHandler#capture_labels` then calls `Repository.from_github_repo_name("VictimOrg/victim-repo")`, finds the real victim `Stack`/`PullRequest`, and does `pull_request.update!(labels: params.pull_request.labels.map(&:name))` — fully attacker-controlled label strings written to a repository whose secret was never checked.

`ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) turns these labels directly into uppercased environment variables merged into the deploy env (`labels[label_name.upcase] = "true"`), with no allow-list or `EnvironmentVariables#permit` filtering at this layer. Since the victim stack has `bot_login` configured (`Shipit.github.bot_login` via `lib/shipit.rb:170-181`, `lib/shipit/github_app.rb:51`), any auto-triggered deploy for that review stack runs as that bot identity, carrying the attacker-injected env vars into `Command`/`PTY.spawn` for the deploy task.

Existing guards do not prevent this: `drop_unhandled_event` only checks the event type exists; `ExplicitParameters` only requires `full_name` be a `String`, not that it match the org used for verification; there is no cross-check anywhere between `repository_owner` and `repository.full_name`; `force_github_authentication`/`User#authorized?`/`stacks` scope are unrelated to unauthenticated webhook ingestion.

### Impact Explanation
This is a payload for one organization/repository (whichever has no `webhook_secret`, or a guessable/weak one) mutating another organization's stack — writing attacker-chosen `PullRequest#labels` on a victim `ReviewStack`, which become environment variables injected into that stack's deploy environment (`ReviewStack#env`), reaching the bot-identity-driven deploy pipeline. This matches "a payload for one repository mutating another's stack" / unauthorized deploy manipulation (Critical, per the target categories), constrained to installations using the **multi-organization** GitHub App configuration (`lib/shipit.rb#github_app_config`) where at least one configured org lacks a `webhook_secret`. It is repeatable against any victim repository/stack as long as `repository.full_name` resolves to an existing `Shipit::Repository`/`ReviewStack`.

### Likelihood Explanation
Preconditions: (1) Shipit configured with the multi-org GitHub App schema (`github: { OrgA: {...}, OrgB: {...} }`), a documented and supported configuration (`docs/setup.md`, `config/secrets.development.shopify.yml`); (2) at least one configured org has no `webhook_secret` set (also a documented/valid state — the example templates show `webhook_secret: # nil`); (3) the victim org/stack has `bot_login` set and review stacks enabled with an existing PR/stack matching `pr<number>` environment naming. Attacker cost is a single crafted, unauthenticated HTTP POST to `/webhooks`; no secrets, sessions, or GitHub permissions are required. This is fully repeatable and scriptable.

### Recommendation
Bind signature verification to the same repository identity the handlers act on: derive `repository_owner` from `repository.full_name`'s owner segment (or require `repository.owner.login` to be present and match `repository.full_name`'s owner) rather than falling back to `organization.login`. Additionally, after signature verification, re-validate in each handler that the resolved `Repository`/`Stack`'s owner matches the org whose secret authenticated the request, rejecting mismatches. Consider dropping the `organization.login` fallback entirely, since it enables verifier/target divergence.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "pull_request opened targeting VictimOrg repo, authenticated via LenientOrg (no webhook_secret), still writes to VictimOrg's stack" do
  # Setup: multi-org config, LenientOrg has webhook_secret: nil, VictimOrg has bot_login set and webhook_secret set.
  # Precondition equality claimed by the code: repository_owner == owner_of(repository.full_name)
  # Actual: repository_owner ("LenientOrg") != owner_of(repository.full_name) ("VictimOrg")

  victim_repo = shipit_repositories(:shipit) # owner: VictimOrg
  review_stack = create_review_stack(repository: victim_repo, number: 42) # environment "pr42"

  payload = {
    action: "opened",
    number: 42,
    pull_request: {
      id: 1, number: 42, url: "...", title: "x", state: "open",
      additions: 1, deletions: 0,
      head: { sha: "a" * 40, ref: "feature" },
      user: { login: "attacker" },
      assignees: [],
      labels: [{ name: "INJECTED_SECRET_ENV" }]
    },
    repository: { full_name: "#{victim_repo.owner}/#{victim_repo.name}" }, # no owner.login sub-object
    organization: { login: "LenientOrg" }, # org with no webhook_secret configured
    sender: { login: "attacker" }
  }.to_json

  post "/webhooks", params: payload, headers: {
    'X-Github-Event' => 'pull_request',
    'X-Hub-Signature' => 'sha1=deadbeef', # bogus/absent, irrelevant for LenientOrg
    'Content-Type' => 'application/json'
  }

  assert_response :ok
  review_stack.pull_request.reload
  assert_includes review_stack.pull_request.labels, "INJECTED_SECRET_ENV"
  assert_equal "true", review_stack.reload.env["INJECTED_SECRET_ENV"]
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L94-114)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
