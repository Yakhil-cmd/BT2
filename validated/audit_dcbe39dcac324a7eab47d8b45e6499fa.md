### Title
Webhook signature verified against `repository.owner.login` while handlers trust `repository.full_name` for repository resolution, enabling cross-repository label injection - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb, app/models/shipit/repository.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/secret to verify the HMAC signature using `params.dig('repository','owner','login')`, but `LabelCapturingHandler#repository` (and every other `pull_request` handler) resolves the target `Shipit::Repository` using the independent field `params.repository.full_name`. Because both fields live in the same attacker-controlled JSON body and are never cross-checked, an attacker who owns Org A can sign a payload with Org A's `webhook_secret` while setting `repository.full_name` to an arbitrary `org-b/repo-b`, causing Org B's `PullRequest#labels` to be overwritten.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't: `organization_whose_secret_verified_signature (derived from repository.owner.login)` == `organization_owning_repository.full_name (used to resolve/mutate the Repository)`.

- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login')` and fetches `github_app = Shipit.github(organization: repository_owner)`, then calls `github_app.verify_webhook_signature(signature, raw_post)` [1](#0-0) [2](#0-1) . `verify_webhook_signature` is a pure HMAC check on the raw JSON bytes against that org's `webhook_secret` [3](#0-2)  - it says nothing about which repository is referenced elsewhere in the body.
- The handler dispatch (`WebhooksController#create`) passes the entire parsed `params` hash, unmodified, to every handler for the event [4](#0-3) .
- `LabelCapturingHandler#repository` resolves the repository purely from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name`, with no comparison to `repository.owner.login` or to the organization that verified the signature [5](#0-4) . `from_github_repo_name` simply splits the string and does a DB lookup [6](#0-5) .
- `LabelCapturingHandler#capture_labels` then persists attacker-chosen labels onto whatever `PullRequest` is found on that resolved stack: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [7](#0-6) .
- Those labels are later merged verbatim into deploy environment variables by `ReviewStack#env`, which uppercases each label name and sets it as an env var: `labels[label_name.upcase] = "true"` [8](#0-7) , feeding into the deploy `Command`/`PTY.spawn` chain for the next deploy on that (victim) `ReviewStack`.

**Attacker's exact request:** POST `/webhooks` with `X-Github-Event: pull_request`, body JSON where `repository.owner.login = "org-a"` (attacker's own org, so `Shipit.github(organization: "org-a")` resolves attacker's app/secret) and `X-Hub-Signature` computed as `HMAC-SHA1(webhook_secret_A, raw_body)`, but `repository.full_name = "org-b/repo-b"` (victim repo) and `pull_request.labels = [{name: "INJECTED_ENV_KEY"}]`, `action: "opened"` or `"labeled"`.

**Why existing guards fail:**
- `verify_signature` only checks the HMAC over the raw bytes against Org A's secret - it succeeds because the attacker legitimately possesses `webhook_secret_A` and can freely craft any JSON content, including a `repository.full_name` unrelated to `repository.owner.login`.
- `drop_unhandled_event` only checks the event type is handled, not the payload consistency.
- The `ExplicitParameters` schema (`params do ... end` in `LabelCapturingHandler`) validates types/presence of `repository.full_name`, `pull_request.labels`, etc., but has no rule that `repository.owner.login == repository.full_name.split('/').first` [9](#0-8) .
- `Repository` model validations (`owner`/`name` format) constrain the string shape only, not which organization's secret is allowed to reference it [10](#0-9) .
- No code anywhere in `WebhooksController`, `Handler`, or `LabelCapturingHandler` compares the app/org tied to the verifying secret against the repository actually mutated.

### Impact Explanation
An attacker who controls only Org A (owns a repo there, knows their own app's `webhook_secret`) can overwrite `PullRequest#labels` on any other Shipit-tracked repository (Org B) whose name they can guess/know, without any interaction from Org B. Because `ReviewStack#env` folds label names directly into the deploy environment as env-var keys, this becomes attacker-controlled environment variable *names* injected into Org B's next deploy process (feeding `Command#unbundled_env` → `PTY.spawn`). This is a cross-tenant write (label data belonging to repo B is set by an unauthenticated-for-B attacker) and, depending on which env var names are chosen (e.g., ones consumed by deploy scripts to select behavior, paths, or feature flags), can influence or subvert the deploy process on Org B's host - matching "a payload for one repository mutating another's stack" and potentially escalating to command execution influence. This is repeatable against any repository name in the Shipit install and across all configured orgs, since the check is purely signature-vs-org, not signature-vs-referenced-repo.

### Likelihood Explanation
Requires: (1) Shipit configured with multiple GitHub Apps/orgs (as documented in `docs/setup.md` and `config/secrets.development.example.yml`/`secrets_double_github_app.yml`), (2) attacker owns/administers at least one org's GitHub App (or any repo under an org with a configured secret) and thus its `webhook_secret`, (3) the target repository (Org B/repo-b) already exists in Shipit's `Repository`/`Stack` tables. No Shipit session, API token, or any Org B secret is required. Attacker cost is a single crafted HTTP POST with a correctly computed HMAC using their own secret - fully repeatable, scriptable, and does not require any live interaction with GitHub.

### Recommendation
In `WebhooksController#verify_signature`, or in `Handler`/`LabelCapturingHandler#repository`, enforce that the organization used to select/verify the webhook secret matches the owner segment of `repository.full_name` before resolving/mutating any repository (e.g., `raise/head(422) unless repository_owner.casecmp?(params.repository.full_name.split('/').first)`). This binding should be validated once at the controller level for all events, not left to each handler.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "signed webhook from org-a cannot mutate a repository belonging to org-b" do
  repo_b = Shipit::Repository.create!(owner: "org-b", name: "repo-b")
  stack_b = repo_b.stacks.create!(environment: "production", branch: "main")
  pr_b = stack_b.create_pull_request!(number: 2, ...) # existing PR fixture for repo-b

  body = JSON.parse(payload(:pull_request_opened))
  body["repository"]["owner"]["login"] = "org-a"       # attacker's own org
  body["repository"]["full_name"] = "org-b/repo-b"     # victim repo, mismatched
  body["pull_request"]["labels"] = [{ "name" => "injected-label" }]
  body["number"] = 2
  raw = body.to_json

  secret_a = "org-a-secret"
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", secret_a, raw)

  Shipit.stubs(:github).with(organization: "org-a")
        .returns(Shipit::GitHubApp.new("org-a", webhook_secret: secret_a))

  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = signature

  post :create, body: raw, as: :json

  assert_response :ok
  # Assert the binding: org whose secret verified != org owning full_name
  assert_not_equal "org-a", body["repository"]["full_name"].split("/").first
  # Assert unauthorized cross-repo mutation occurred
  assert_includes pr_b.reload.labels, "injected-label"
end
```
This demonstrates the equality `repository_owner (org-a)` vs `repository.full_name.split('/').first (org-b)` diverges, no guard rejects it, and repo-b's `PullRequest#labels` is mutated by an attacker who never held org-b's secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L8-39)
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

**File:** app/models/shipit/repository.rb (L41-45)
```ruby
    validates :name, uniqueness: { scope: %i[owner], case_sensitive: false,
                                   message: 'cannot be used more than once' }
    validates :owner, :name, presence: true, ascii_only: true
    validates :owner, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: OWNER_MAX_SIZE }
    validates :name, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: NAME_MAX_SIZE }
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
