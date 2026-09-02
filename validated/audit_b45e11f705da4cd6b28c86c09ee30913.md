### Title
`pull_request`/`reopened` webhook signature checked against `repository.owner.login`, but the handler mutates the stack resolved from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` used to authenticate the webhook based on `repository_owner` (`params.dig('repository','owner','login')` with a fallback to `params.dig('organization','login')`), while `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler` resolves the mutated `Repository`/`ReviewStack` using the independent field `params.repository.full_name`. Because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected organization has no `webhook_secret` configured, an attacker who names a no-secret org as `repository.owner.login` while pointing `repository.full_name` at a different org's real repository can get a forged `reopened` event accepted and applied against that other org's `ReviewStack`.

### Finding Description
The broken binding is the implicit assumption: `repository_owner (used to select the signing key) == owner(repository.full_name) (used to resolve the mutated repository/stack)`. Nothing in the code enforces this equality.

- Signature selection: `verify_signature` calls `Shipit.github(organization: repository_owner)` and `repository_owner` reads only `params.dig('repository','owner','login')` (or `params.dig('organization','login')`). [1](#0-0) [2](#0-1) 
- Trivial bypass for no-secret orgs: `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for that org, so any request, with any/no signature, is treated as verified for orgs without a configured secret. [3](#0-2) 
- Handler resolution is independent of the field used for signature selection: `ReopenedHandler#repository` resolves via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, and `from_github_repo_name` simply splits `full_name` on `/` to get owner/name and looks up the `Repository` record - it has no relation to `repository.owner.login`. [4](#0-3) [5](#0-4) 
- The resolved `repository` drives the mutated `ReviewStack` scope (`repository.review_stacks`), and `ReopenedHandler#process` calls `stack.unarchive!`, which for a missing/archived `ReviewStack` either creates a new one or unarchives (re-provisions) an existing one. [6](#0-5) [7](#0-6) 

Exploit flow: attacker crafts a `pull_request` webhook body with `action: "reopened"`, `repository.owner.login = "orgA"` (an org configured in `secrets.github` with `webhook_secret: nil`), and `repository.full_name = "orgB/victim-repo"` (a real repository belonging to a different, properly-secured org `orgB`). They POST it to `/webhooks` with header `X-Github-Event: pull_request` and an arbitrary/absent `X-Hub-Signature`. `verify_signature` looks up `Shipit.github(organization: "orgA")`, whose `verify_webhook_signature` short-circuits to `true` because `orgA` has no secret. The request passes to `ReopenedHandler`, which resolves the real `orgB/victim-repo` `Repository` from `full_name` and unarchives/creates its `ReviewStack`, entirely bypassing `orgB`'s actual webhook secret.

Existing guards fail because: (1) `drop_unhandled_event`/`ExplicitParameters` schema only validate shape, not the owner-consistency invariant; (2) `verify_signature` never cross-checks that `repository_owner` matches the owner segment of `repository.full_name`; (3) `GithubOrganizationUnknown` rescue only fires when the named org has no config at all, not when it exists but has no secret; this exact split (verifying against one org's config while mutating another org's resolved repository) is unguarded in this codebase.

### Impact Explanation
An unauthenticated, unprivileged attacker (any HTTP client, no GitHub org membership or Shipit credentials required) can forge state-changing GitHub events for a specific victim repository/stack—provided only that some other, unrelated org in the same Shipit deployment has no `webhook_secret` configured. This matches "a payload for one repository mutating another's stack" (Critical), since `ReopenedHandler` unarchives/re-provisions a `ReviewStack` (triggering deprovisioning/reprovisioning, CI/CD side effects) for `orgB`'s repository without ever presenting `orgB`'s valid signature. The attack is repeatable against any repository whose owner/full_name the attacker knows, as long as at least one configured org in `Shipit.github_organizations` lacks a secret; multi-org deployments (as documented in "Using Multiple Github Applications") are the direct target of this configuration pattern.

### Likelihood Explanation
Requires: (1) the target Shipit instance to use the multi-org `github:` config schema with at least one org lacking `webhook_secret`; (2) knowledge of a victim `org/repo` full_name that has `review_stacks_enabled` and a provisioning behavior that would accept the reopened event (`allow_all`, or label-based logic satisfied by attacker-controlled PR labels since the attacker's own PR data is echoed in the payload). Attacker cost is a single unauthenticated POST; no secrets, sessions, or GitHub write access are needed. This is feasible and repeatable at will.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, verify using the organization that will actually be used to resolve the affected repository/stack (i.e., derive the verifying org strictly from `repository.full_name`'s owner segment, not `repository.owner.login`), or enforce that `repository.owner.login` (case-insensitively) equals the owner segment parsed from `repository.full_name` before selecting the `GitHubApp`, rejecting (422) on mismatch. Additionally, consider requiring an explicit `webhook_secret` for every configured org (fail closed rather than treating a missing secret as "always verified").

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (using the double-org fixture `test/dummy/config/secrets_double_github_app.yml`, where both `OrgOne` and `OrgTwo` have `webhook_secret: nil`, adapted so only one org lacks a secret and the other has one configured):

```ruby
test "pull_request reopened forged for no-secret org affects a different org's repository" do
  # Setup: OrgA has no webhook_secret; OrgB (owner of the real repository/stack) requires a secret.
  repo = shipit_repositories(:orgb_repo) # owner: "orgb", name: "repo"
  review_stack = ... # existing archived ReviewStack under repo, environment "pr123"

  payload = {
    action: "reopened",
    number: 123,
    pull_request: { id: 1, number: 123, url: "...", title: "x", state: "open",
                     additions: 1, deletions: 0,
                     head: { sha: "abc", ref: "feature" },
                     user: { login: "attacker" }, assignees: [], labels: [] },
    repository: { owner: { login: "orga" }, full_name: "orgb/repo" }, # split: verifies as orga, mutates orgb
    sender: { login: "attacker" }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid for OrgB

  assert review_stack.archived?
  post :create, body: payload, as: :json
  assert_response :ok

  review_stack.reload
  # Binding under test: repository_owner ("orga", used for signature verify) != owner("orgb/repo") (used to mutate stack)
  # Both sides do NOT match, yet the mutation still succeeded -> vulnerability confirmed.
  assert_not review_stack.archived?
end
```

This demonstrates the exact broken equality: `repository_owner` used to select the verifying `GitHubApp` diverges from the owner of `repository.full_name` used to locate and mutate the `ReviewStack`, and the request still succeeds because `orga` has no `webhook_secret`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
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
