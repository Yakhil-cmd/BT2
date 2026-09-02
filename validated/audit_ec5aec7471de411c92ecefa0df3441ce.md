### Title
Webhook signature is verified against the org derived from `repository.owner.login`, but events are applied to whatever repository `repository.full_name` names - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-App deployment, `WebhooksController` selects which organization's `webhook_secret` to HMAC-verify a webhook against using one field of the untrusted JSON body (`repository.owner.login` / `organization.login`), while the event handlers that actually mutate state select the target `Repository`/`Stack` using a *different* field of the same body (`repository.full_name`). Nothing binds these two fields together before the signature check passes, so a request signed with organization A's secret can be made to act on a repository that Shipit tracks under organization B.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the HMAC secret) to validate the payload with, purely from attacker-supplied JSON: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (`app_id`, `private_key`, `webhook_secret`) keyed by exactly that attacker-controlled string: [3](#0-2) 

Once `verify_webhook_signature` returns true, `create` dispatches the same raw JSON body to the registered handlers: [4](#0-3) 

But every handler resolves the target `Repository`/`Stack` from a *different* JSON field - `repository.full_name` - not from the `repository.owner.login`/`organization.login` value that was used to select the verification secret: [5](#0-4) 

`PushHandler` and `StatusHandler` both rely on this shared `stacks`/`repository_name` helper: [6](#0-5) [7](#0-6) 

The equality that should hold but doesn't:
`organization used to select/verify the HMAC secret (repository.owner.login)` == `organization/repository whose Stack state is mutated (repository.full_name)`.

Concretely, docs confirm multiple independently-configured organizations, each with its own (optional) `webhook_secret`: [8](#0-7) 

and `verify_webhook_signature` treats an *unset* secret for any configured organization as automatic success: [9](#0-8) 

So if Shipit is configured for at least two GitHub orgs (a common documented deployment pattern) and any one of them has no `webhook_secret` configured (also documented as valid: `webhook_secret: # nil`), an attacker who knows/controls that low-security organization's name can send a POST to `/webhooks` with:
- `repository.owner.login` (or `organization.login`) = the weak/unsecreted org — this passes `verify_signature` unconditionally.
- `repository.full_name` = `"strong-org/tracked-repo"` — a repository actually tracked by Shipit under the strongly-secured GitHub App.

The handler layer never re-checks that `repository.owner.login` matches the owner segment of `repository.full_name`, so the forged event is applied to the strong org's `Stack` (e.g. `StatusHandler` writes a fabricated commit status via `Commit#create_status_from_github!`, or `PushHandler` triggers `stack.sync_github`) even though the request was never actually signed by the strong org's GitHub App.

### Impact Explanation
This lets an unprivileged attacker who only needs knowledge of an organization name that is configured with no/known `webhook_secret` write fabricated GitHub event data (commit statuses, push-triggered syncs, membership/team changes, PR label/merge metadata depending on which handlers are enabled) into a Stack that belongs to an entirely different, correctly-secured GitHub organization. Forged commit statuses can flip Shipit's merge-readiness/CI gating (`Status`) for a tracked repository, which can unblock or trigger deploys/merges that should have required a real, signed CI signal from GitHub — an unauthorized-deploy-class impact via a credential-boundary (organization authentication) that doesn't match the resource (repository) being written.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment (documented as a first-class supported configuration), and (2) at least one configured organization with a weak/absent `webhook_secret`, or knowledge of any configured org's leaked webhook secret. Given this precondition, the attack is a single unauthenticated HTTP POST with a crafted JSON body — no session, API token, or GitHub write access is needed. The precondition (mixed-strength multi-org webhook secrets) is plausible but not universal, which is why I frame this as an analog of the reported bug class rather than a certainty about any specific production configuration.

### Recommendation
Bind the two identifiers before trusting the payload: after `verify_signature` succeeds, re-derive the organization from `repository.full_name` (or `organization.login`) inside the handler dispatch path and reject/`422` if it does not match the organization whose secret was used to verify the signature in `WebhooksController#verify_signature`. Alternatively, verify the signature using the secret belonging to the organization that owns the `Repository`/`Stack` actually targeted by `full_name`, rather than trusting the unauthenticated `repository.owner.login`/`organization.login` field to pick the verification key.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`) with two organizations: `weak-org` (no `webhook_secret`) and `strong-org` (real GitHub App + secret), each with tracked repositories/stacks.
2. Shipit tracks `strong-org/tracked-repo` as a `Stack`.
3. Attacker sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything

{
  "sha": "<victim commit sha in strong-org/tracked-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "full_name": "strong-org/tracked-repo", "owner": { "login": "weak-org" } }
}
```
4. `WebhooksController#repository_owner` returns `"weak-org"`; `Shipit.github(organization: "weak-org")` has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally [9](#0-8) .
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` and calls `create_status_from_github!` using `repository.full_name` semantics inherited from `Handler#repository_name`, writing a forged `success` status onto the `strong-org` commit despite the request never being signed by `strong-org`'s GitHub App [5](#0-4) [7](#0-6) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** docs/setup.md (L181-209)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
