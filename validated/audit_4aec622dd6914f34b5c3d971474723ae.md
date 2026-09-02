### Title
Repository-scope confusion in webhook signature verification allows attacker to mutate a victim repository's ReviewStack via `PullRequest::ReopenedHandler` - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`WebhooksController#verify_signature` derives the organization used to select the HMAC secret from `params.dig('repository', 'owner', 'login')`, while every `PullRequest` handler (including `ReopenedHandler`) resolves the target `Repository`/`ReviewStack` from the independent field `params.repository.full_name`. These two fields are never cross-validated, so a forged payload can present one org for signature verification and a different `owner/name` for the actual repository/stack mutation.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't: `verify_signature`'s authenticated org (`params.dig('repository','owner','login')`) == the org embedded in `params.repository.full_name` used by `Repository.from_github_repo_name` to pick the mutated repository/stack. [1](#0-0)  checks the signature against `Shipit.github(organization: repository_owner)` where `repository_owner` comes solely from `repository.owner.login` [2](#0-1) . `ReopenedHandler#repository` instead resolves the target repo from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name` [3](#0-2) , which simply splits the string on `/` [4](#0-3) . The `ExplicitParameters` schema only requires `repository.full_name` to be a `String` [5](#0-4)  — nothing enforces that `full_name`'s owner segment matches `repository.owner.login`.

Additionally, `verify_webhook_signature` fails open when no secret is configured for the resolved org: `return true unless webhook_secret` [6](#0-5) . Combined with the independent-field issue, an attacker who can name (or control) an org in Shipit's multi-org config that has no `webhook_secret` set can send `repository.owner.login = "no-secret-org"` (trivially verified) while `repository.full_name = "victim-org/victim-repo"`, causing `ReopenedHandler` to resolve and mutate the victim's `Repository`/`ReviewStack`.

Once `unarchive?`/`respond_to_pull_request_reopened?` pass (subject to the victim's own `review_stacks_enabled`/provisioning policy, which are legitimate victim-side settings, not attacker-controlled), `ReviewStackAdapter#unarchive!`/`create!` reads `branch: params.pull_request.head.ref` directly from the attacker's payload [7](#0-6)  to build/respin the victim's stack.

Existing guards do not stop this: `drop_unhandled_event` and `check_if_ping` are unrelated; `verify_signature` only validates that the *stated* `repository.owner.login` org's secret matches — it never checks that this org matches the org embedded in `repository.full_name` that handlers actually act on.

### Impact Explanation
An attacker with no Shipit credentials can trigger unauthorized re-provisioning (build/deploy trigger) of a victim's ReviewStack using an attacker-chosen head sha/ref, as long as some org configured in the Shipit instance (their own, or any org lacking a webhook secret) can be named in `repository.owner.login` while `repository.full_name` targets the victim. This is a payload for one repository/org mutating another repository's stack — matching the Critical impact category. Repeatable against any repository with `review_stacks_enabled` and a matching provisioning policy, for any PR number.

### Likelihood Explanation
Requires: (a) a Shipit deployment with multi-org GitHub App configuration where at least one configured org has no `webhook_secret`, or an org the attacker otherwise controls signing for; (b) the victim repository has `review_stacks_enabled` and a provisioning policy that doesn't block (`allow_all`, or label-based policy attacker can satisfy on their own fabricated `labels` array in the payload); (c) attacker must know/guess a valid `owner/name` and PR number for the victim (both easily discoverable, e.g. from the public GitHub repo). This is a configuration-dependent gap (per-org webhook secret must be unset for at least one configured org), which is plausible in real multi-org Shipit deployments given the documented "optional per-org secret" design in `config/secrets.*.yml` examples.

### Recommendation
Cross-validate `repository.owner.login` against the owner segment of `repository.full_name` (and against `organization.login` when present) before dispatching to handlers, rejecting mismatches. Also consider requiring `webhook_secret` to be present for all configured orgs (fail closed instead of fail open when blank), and have handlers resolve the target `Repository` using the same verified `repository_owner`/org context established during signature verification rather than re-parsing untrusted `full_name`.

### Proof of Concept
```ruby
test "reopened webhook with mismatched owner.login vs full_name mutates victim repository" do
  # victim repo has review_stacks_enabled + allow_all provisioning, org "victimorg"
  # Shipit config has org "noSecretOrg" with webhook_secret: nil

  payload = {
    action: "reopened",
    number: 42,
    pull_request: {
      id: 1, number: 42, url: "https://x", title: "t", state: "open",
      additions: 1, deletions: 0,
      head: { sha: "attackersha", ref: "attacker-branch" },
      user: { login: "attacker" },
      assignees: [], labels: []
    },
    repository: { full_name: "victimorg/victimrepo", owner: { login: "noSecretOrg" } },
    sender: { login: "attacker" }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  # no X-Hub-Signature needed since noSecretOrg has no webhook_secret -> verify returns true

  assert_difference -> { Shipit::ReviewStack.where(environment: "pr42").count }, 1 do
    post :create, body: payload, as: :json
  end

  stack = Shipit::ReviewStack.find_by(environment: "pr42")
  assert_equal "victimorg", stack.repository.owner
  assert_equal "attacker-branch", stack.branch
end
```
Assert on both sides of the equality: `repository_owner` (`"noSecretOrg"`) used by `verify_signature` != owner segment of `params.repository.full_name` (`"victimorg"`) resolved by `Repository.from_github_repo_name`, yet the request succeeds and mutates `victimorg`'s stack.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
