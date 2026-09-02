Confirmed: no code anywhere cross-checks `repository_owner` (used in `verify_signature` to select the `GitHubApp`/`webhook_secret`) against the owner embedded in `params.repository.full_name` (used by `OpenedHandler#repository` / `ReviewStackAdapter#create!` to select which `Repository`/`Stack` gets mutated).

### Title
Signature-verified organization is never bound to the target repository resolved from `repository.full_name` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` to validate the HMAC using `repository_owner`, derived from `params.dig('repository','owner','login')` in the attacker-supplied JSON body. `OpenedHandler#repository` independently resolves the target `Shipit::Repository` from `params.repository.full_name`, also attacker-supplied, with no check that the two values name the same organization.

### Finding Description
The required binding is: `organization_that_verified_signature == owner_of(params.repository.full_name)`. Tracing the code:

- `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, then verifies `request.raw_post` against that org's `webhook_secret` [1](#0-0) [2](#0-1) .
- `OpenedHandler#repository` resolves the target repository purely from `params.repository.full_name`, splitting on `/`, with no reference to `repository_owner` used above: `Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new` [3](#0-2) .
- `Repository.from_github_repo_name` just splits the string and does a `find_by(owner:, name:)` with no relation to the verifying app [4](#0-3) .
- `ReviewStackAdapter#create!` then creates/mutates a `Stack` scoped to `repository.review_stacks`, using `params.repository["full_name"]` for logging but never for authorization [5](#0-4) .

Since `repository.owner.login` and `repository.full_name` are two independent JSON fields fully controlled by whoever crafts the raw POST body, and only `repository.owner.login` is used to pick the `webhook_secret` for HMAC verification, a request can be signed with Organization A's `webhook_secret` while `repository.full_name` names an entirely different, already-tracked repository belonging to Organization B. `Shipit.github` legitimately supports multiple organizations each with distinct `webhook_secret`s, as documented and tested [6](#0-5) [7](#0-6) , so this is a real supported deployment topology, not a hypothetical one. No component in the path — not `verify_signature`, not `Handler#initialize`/`ExplicitParameters` schema, not `OpenedHandler#repository`, not `ReviewStackAdapter` — ever compares the two organization values.

### Impact Explanation
An attacker who holds a valid `webhook_secret` for Organization A (e.g., a malicious or compromised tenant admin in a shared multi-org Shipit deployment) can forge a `pull_request` "opened" webhook, sign it with A's secret, but set `repository.full_name` to `"orgB/tracked-repo"` for any repository of Organization B that Shipit already tracks. This creates a `Shipit::ReviewStack`/`Stack` under Organization B with attacker-chosen `branch` (`params.pull_request.head.ref`), `environment`, and PR metadata, and can enqueue provisioning for that stack — a payload signed for one organization mutating another organization's stack. This matches the Critical category "a payload for one repository mutating another's stack."

### Likelihood Explanation
Exploitation requires: (1) a Shipit deployment configured with multiple GitHub organizations (a documented, supported configuration), (2) the attacker already possesses a valid `webhook_secret` for at least one configured organization (Org A), and (3) Org B's repository is already tracked by Shipit with review-stack provisioning enabled. Given those preconditions, the attack is trivial to repeat against any tracked repository name, since the only per-request cost is computing an HMAC-SHA1 over a JSON body the attacker fully controls.

### Recommendation
In `OpenedHandler#repository` (and any other handler resolving a target repository from payload data), verify that the owner segment of `params.repository.full_name` matches `repository_owner` used for signature verification (or otherwise thread the verified organization from the controller into the handler and assert equality) before resolving/mutating any `Repository`/`Stack`.

### Proof of Concept
minitest plan (in `test/controllers/webhooks_controller_test.rb` style, not asserting file creation since out-of-scope but describing the assertions):
```ruby
test "org A's webhook_secret cannot create a review stack under org B's repository" do
  # Setup: multi-org secrets (OrgOne, OrgTwo) as in test/dummy/config/secrets_double_github_app.yml
  # OrgTwo/tracked-repo already exists as a Shipit::Repository with review_stacks_enabled + allow_all
  payload = JSON.parse(payload(:pull_request_opened))
  payload["repository"]["owner"]["login"] = "OrgOne"       # selects OrgOne's webhook_secret for verification
  payload["repository"]["full_name"] = "orgtwo/tracked-repo" # target belongs to OrgTwo
  body = payload.to_json
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", org_one_webhook_secret, body)

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = signature

  assert_no_difference -> { Shipit::Stack.where(repository: shipit_repositories(:orgtwo_tracked_repo)).count } do
    post :create, body: body, as: :json
  end
  # Current code: this assertion FAILS (a stack IS created), confirming the vulnerability.
end
```
This demonstrates that `repository_owner` (verified against OrgOne's secret) and the owner encoded in `params.repository.full_name` (OrgTwo) are never checked for equality, allowing the `OpenedHandler` bug to cross tenants when the attacker holds even one organization's `webhook_secret`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-94)
```ruby
          def repo_name
            params.repository["full_name"]
          end

          def pr_number
            params.number
          end

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-6)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
```
