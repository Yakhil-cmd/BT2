### Title
Cross-organization forged webhook: signature verification keyed on payload-supplied organization while handlers act on payload-supplied repository full_name - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` used to validate `X-Hub-Signature` based solely on an attacker-controlled field of the *same* unauthenticated JSON body (`repository.owner.login`, falling back to `organization.login`), while every webhook `Handler` (push, status, pull_request, membership, check_suite) independently resolves the target `Repository`/`Team`/`Stack` from other attacker-controlled fields of that same body (`repository.full_name`, `organization.login`). Nothing binds "the organization whose secret produced a valid signature" to "the repository/organization that is actually mutated."

### Finding Description
`verify_signature` computes: [1](#0-0) 
using `repository_owner`, itself taken straight from the JSON body: [2](#0-1) 

`Shipit.github(organization:)` then looks up a per-organization `webhook_secret` from `config/secrets.yml` under the "Using Multiple GitHub Applications" scheme: [3](#0-2) [4](#0-3) 

`verify_webhook_signature` is a plain HMAC-SHA1 comparison of the raw body against whichever organization's secret was selected: [5](#0-4) 

Crucially, the check only proves the request was signed with *some* configured org's secret — it does not prove that the repository/organization named later in the payload and used to select what gets mutated is the one that owns that secret. All downstream handlers derive the acted-upon `Repository` purely from other fields of the same untrusted body: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) 

**The equality that should hold but doesn't:**
`organization(signature) == organization(repository acted upon)`

Before the bug (single-org config, or where handlers can't be pointed elsewhere): the only key available is the global secret, so this is moot. After a multi-tenant deployment adopts the documented multi-org `github:` config (each org configured with its own `webhook_secret`, exactly as `docs/setup.md` instructs): an entity that legitimately administers OrgA's GitHub App (and therefore knows OrgA's `webhook_secret`, since the app owner sets it at creation time and it is copied verbatim into Shipit's config) can craft an arbitrary raw JSON body where:
- `repository.owner.login` (or `organization.login`) = `"OrgA"` → drives secret selection, passes signature check using the known OrgA secret.
- `repository.full_name` = `"OrgB/some-other-stack"` (or, for the `membership` handler, `organization.login = "OrgB"`) → drives the actual mutation.

This is a direct analog of the M-11 report's pattern: two computations meant to reference the same logical entity (`previousMagnitude` vs. the position actually being processed) diverge because one is derived from stale/wrong state instead of the value under evaluation. Here, "the org that authenticated" and "the org/repo that is written" are computed from two different sub-fields of the same untrusted document with no equality constraint enforced between them.

### Impact Explanation
An attacker who controls (or knows the webhook secret of) only one tenant organization in a multi-org Shipit deployment can forge webhooks that are accepted as authentic for a *different* organization's repositories. Depending on handler:
- `PushHandler`: triggers `stack.sync_github(expected_head_sha:)` for OrgB's stacks (unwanted cross-repository sync/state changes) — [11](#0-10) 
- `StatusHandler`: injects forged CI status onto OrgB's commits via `commit.create_status_from_github!`, which can flip `deployable?` and enable an unauthorized deploy of OrgB code — [8](#0-7) 
- `MembershipHandler`: adds/removes arbitrary GitHub users to/from OrgB's `Team` records used for `Shipit.github_teams` authorization — [9](#0-8) 
- `PullRequest` handlers: create/archive review stacks for OrgB repos.

This crosses the "cross-repository writes" and "escalation into `Shipit.github_teams` authorization" impact categories explicitly listed as in-scope Critical/High impacts.

### Likelihood Explanation
Requires: (1) the Shipit deployment to use the multi-organization `github:` secrets layout (a documented, supported configuration, not a misconfiguration), and (2) the attacker to be an administrator of at least one onboarded organization's GitHub App (i.e., they legitimately know that org's `webhook_secret` because they set it up), without needing any access to the target organization, its repositories, or the Shipit host itself. This is a realistic "unprivileged relative to the victim org" attacker and does not require an `ApiClient` token, GitHub App private key, TLS interception, or social engineering.

### Recommendation
Bind the two computations together instead of deriving them independently from untrusted input:
- After locating the GitHub App config via `repository_owner` and verifying the signature, re-derive/validate that every `repository.full_name` / `organization.login` referenced later in the same payload belongs to that same verified organization before dispatching to handlers (e.g., assert `full_name.split('/').first.casecmp(repository_owner) == 0`), or
- Verify the signature against **all** configured organizations' secrets (not just the one named by the untrusted payload) and only proceed if the org that actually matches the signature is the org that owns the acted-upon repository.

### Proof of Concept
1. Configure Shipit with the multi-org scheme from `docs/setup.md` (`config/secrets.yml` → `github: { OrgA: {webhook_secret: SECRET_A, ...}, OrgB: {webhook_secret: SECRET_B, ...} }`), with stacks for both `OrgA/repoA` and `OrgB/repoB`.
2. As the administrator of OrgA's GitHub App (who legitimately knows `SECRET_A`), construct a raw JSON push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": {"login": "OrgA"},
    "full_name": "OrgB/repoB"
  }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(SECRET_A, raw_body)` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` selects `Shipit.github(organization: "OrgA")`, validates the HMAC successfully (since it was signed with `SECRET_A`), and the request proceeds.
5. `Shipit::Webhooks::Handlers::PushHandler#process` resolves `repository_name` as `"OrgB/repoB"` and calls `stack.sync_github(expected_head_sha: ...)` on OrgB's stack — despite the request never being signed by OrgB's secret. Analogous crafted payloads against `status` or `membership` events achieve forged CI statuses or team membership changes on OrgB.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
