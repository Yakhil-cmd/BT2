### Title
Webhook signature verified against `repository.owner.login` while stack/repository actions are authorized against `repository.full_name` in the same payload - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check based on `params.dig('repository', 'owner', 'login')` (or `organization.login`), but every `Webhooks::Handlers::Handler` subclass resolves *which* `Repository`/`Stack` to mutate using a **different field of the same JSON body**: `payload.dig('repository', 'full_name')`. This is analogous to the Tigris `mint()` finding: the verified/bound value (owner used for the secret lookup) is not the same value later trusted for the state-mutating action (`full_name` used for repository lookup).

### Finding Description
`verify_signature` picks the GitHub App/secret with:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 
and verifies the raw body against that org's `webhook_secret` [2](#0-1) , using `GitHubApp#verify_webhook_signature` which HMACs the entire raw payload [3](#0-2) .

Once verification passes, every handler (`PushHandler`, `Handler#stacks`, and all `pull_request/*` handlers) resolves the target `Repository` with a **separate** field, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`Repository.from_github_repo_name` splits `"owner/name"` and looks the repository up by that pair [5](#0-4) .

Because Shipit supports multiple GitHub organizations, each with its own `webhook_secret` in `Shipit.github(organization: ...)` config [6](#0-5) , and the verification key is looked up from `repository.owner.login` while the actual mutated resource is looked up from `repository.full_name`, the binding the controller actually enforces is:

`verified_secret_for(payload.repository.owner.login) == HMAC(raw_body)`

but the binding the handler *needs* to hold for authorization is:

`payload.repository.full_name (owner+name) == repository actually mutated`.

Since the whole raw body is what's HMAC'd, GitHub itself keeps these two fields consistent when *it* sends a real webhook for a real repo (both `owner.login` and `full_name`'s owner segment come from the same authentic GitHub-generated body, and GitHub always signs with the secret configured for the repository owner it is actually pushing/notifying about). This makes real-world exploitation depend on a scenario where Shipit's own configuration allows one `webhook_secret` to legitimately authenticate deliveries whose `full_name` differs from `owner.login`; the codebase does not appear to encode any assertion that `full_name`'s owner segment matches `repository.owner.login`, so this equality is implicit/assumed rather than enforced in code.

### Impact Explanation
If it were possible to obtain a webhook signed with an organization's secret but with a `repository.full_name` referencing a *different* organization's repository (e.g., a repository transfer, a payload replayed across orgs, or any GitHub event type where the `owner.login` and `full_name` fields can diverge, such as `membership`/`organization` events which key off `organization.login` rather than `repository`), the handler would perform its authorized action (`sync_github`, archive/unarchive, `PullRequest#update`, `Team`/`Membership` creation) against a stack/repository belonging to a **different owner** than the one whose secret was actually verified. This would allow cross-repository state changes triggered through valid signatures scoped to the wrong repository — matching the report's core damage class (state mutated using an identifier that was never covered by the same check that authorized the action).

### Likelihood Explanation
Low-to-moderate confidence this is concretely exploitable as written, because in the common single/legacy config (`github_default_organization`) there is only one secret for all repos, making the owner/`full_name` split moot, and for genuine GitHub deliveries the two fields are always consistent by construction. The risk surfaces only in multi-org deployments (`Shipit.github(organization: ...)` per-org secrets) where an attacker or a misdelivery could produce a validly-signed body (signed by org A's secret) whose `repository.full_name` names a repo under org B, and Shipit has no explicit check tying `owner.login` to `full_name`'s owner. This is a structural analog of the reported bug class (verified field ≠ acted-upon field) rather than a demonstrated exploit chain, since I could not find/confirm an attacker-reachable path to actually forge such a cross-owner payload without already controlling one organization's `webhook_secret`.

### Recommendation
In `WebhooksController#verify_signature` (or in `Webhooks::Handlers::Handler`), assert that the owner segment of `repository.full_name` equals `repository.owner.login` (or `organization.login`) before dispatching to handlers, so the value used to select the verification secret is provably the same value used to select the mutated repository/stack.

### Proof of Concept
Not independently demonstrable from the indexed engine code alone: constructing a payload where `repository.owner.login` (used for secret selection) differs from the owner segment of `repository.full_name` (used for repository lookup) would require either control of a legitimate `webhook_secret` for one configured organization or a GitHub delivery quirk not visible in this codebase. This is reported as a structural analog rather than a confirmed working exploit given the available index; a full assessment (e.g., of whether GitHub can ever emit such a mismatched payload, or whether multi-org configs are common) would require a live Devin session with full repository access.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
