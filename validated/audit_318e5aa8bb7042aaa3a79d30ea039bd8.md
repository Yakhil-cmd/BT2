### Title
Webhook `status` events are scoped globally by commit SHA, not by repository, allowing a signature verified against one organization's secret to forge CI status on any other stack's commit - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify a payload against using an *unverified* field extracted from the same JSON body (`repository.owner.login` / `organization.login`), then verifies the HMAC signature using that org's secret. `StatusHandler`, which processes `status` events, never re-checks that the payload's `repository` matches the commit it updates — it looks up commits globally by SHA (`Commit.where(sha: params.sha)`) across the entire Shipit instance. This breaks the binding "organization that authenticated == repository that is written": a payload can authenticate as Org A (using Org A's webhook secret) while writing a commit status to a commit that belongs to a completely unrelated stack/repository/org B.

### Finding Description
`Shipit::WebhooksController#verify_signature` computes `repository_owner` from the raw JSON body itself before the signature has been validated: [1](#0-0) [2](#0-1) 

The signature is then verified against the secret configured for that `organization` via `Shipit.github(organization:)`, which supports a multi-organization config keyed by org name: [3](#0-2) 

This design assumes the organization used to pick the verification secret always matches the repository the payload subsequently acts on. That assumption is not enforced for `status` events. `StatusHandler#process` resolves the target purely by commit SHA, with no scoping to the repository/organization named in the payload: [4](#0-3) 

Compare this to other handlers (push, pull_request) which correctly scope lookups through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching any stack: [5](#0-4) [6](#0-5) 

`StatusHandler` is the outlier: it never calls `repository_name`/`stacks`, so the `repository` object in the payload is only used by `verify_signature` to pick the secret — the actual database write (`commit.create_status_from_github!`) is keyed solely on `sha`, which is global across all stacks/orgs in the Shipit instance.

### Impact Explanation
An attacker who controls (or has legitimate webhook access to) any single organization/repository configured in a multi-org Shipit deployment — i.e., they know that org's `webhook_secret` because they set up the GitHub App/webhook for their own org — can craft a forged `status` webhook payload:
- `repository.owner.login` (or `organization.login`) = their own org (so `verify_signature` picks their known secret and the HMAC validates)
- `sha` = the SHA of a commit belonging to a *different*, unrelated stack/repository in the same Shipit instance (SHAs are public information visible on GitHub)
- `state` = `success`, plus a matching `context` for one of that stack's `ci.require` contexts

Because `StatusHandler` does not check that `sha` belongs to a commit under the authenticated organization's repository, the forged status is written to the victim commit. This can flip `Commit#deployable?` to true (via `success?` in `Status::Group`), satisfying required CI checks and enabling `schedule_continuous_delivery`/manual deploy of a commit that never actually passed CI in the victim's real CI system — i.e., an unauthorized deploy of code that should have been blocked, reachable purely by webhook forgery with no Shipit session, `ApiClient` token, GitHub App private key, or repository write access on the victim repo. This satisfies the "High: escalation ... unauthenticated read/write of stack state" / "unauthorized deploy" impact bar via the escalation from one org's authenticated boundary into another org's commit state.

### Likelihood Explanation
This requires:
1. A Shipit deployment configured with the multi-organization GitHub config schema (`Shipit.github_organizations` > 1), which is an explicitly supported and documented configuration.
2. Attacker knowledge of any one org's `webhook_secret` in that deployment (trivial if the attacker is the admin who registered their own org's GitHub App/webhook with Shipit, or if it's ever set to blank/predictable — `verify_webhook_signature` even auto-passes when no secret is configured).
3. Knowledge of the target commit's SHA (public on GitHub) and a required CI context name (typically discoverable from the target repo's `shipit.yml`/CI config, which is often public).

No credentials scoped to the victim repository, no `ApiClient` token, and no GitHub write access to the victim repo are needed — only webhook signature knowledge for an unrelated org. This is a realistic, low-friction path for any admin of one onboarded org to affect deploy gating for any other onboarded org sharing the same Shipit instance.

### Recommendation
In `StatusHandler` (and any other handler that trusts payload-embedded identifiers without further checks), scope the commit lookup by the repository named in the payload, verified against the same organization that produced a valid signature:
```ruby
def process
  Commit.joins(stack: :repository)
        .where(sha: params.sha, shipit_repositories: { name: ..., owner: ... })
        .each { |commit| commit.create_status_from_github!(params) }
end
```
More robustly, `verify_signature` should not rely on attacker-controlled payload fields to select the verification secret when it's used purely to find *some* valid signature; alternatively, once verified, the controller should pass along the resolved `repository_owner`/organization to each handler so every handler (not just push/pull_request) enforces that the org used to authenticate matches the org that owns the resource being mutated.

### Proof of Concept
1. Deploy Shipit with multi-org config: `github: { orga: {webhook_secret: "secretA", ...}, orgb: {webhook_secret: "secretB", ...} }`, with stacks for both `orgA/repo1` and `orgB/repo2`.
2. Attacker controls org A's GitHub App/webhook (knows `secretA`).
3. Attacker observes (publicly, via GitHub) a commit SHA `deadbeef...` on `orgB/repo2` that is pending/failing a required CI context `ci/tests`.
4. Attacker POSTs to `/webhooks` with header `X-Github-Event: status`, body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "orgA" } }
}
```
signed with `X-Hub-Signature: sha1=<HMAC-SHA1(secretA, raw_body)>`.
5. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches `secretA`, and the signature validates.
6. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")`, finds the commit belonging to `orgB/repo2`'s stack, and creates a `success` status for it — even though the attacker has no access whatsoever to `orgB`.
7. If `orgB/repo2`'s stack has continuous deployment enabled and this was the last blocking status, `schedule_continuous_delivery` triggers an unauthorized deploy.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
