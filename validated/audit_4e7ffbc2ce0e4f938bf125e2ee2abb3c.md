### Title
Signature verified against attacker's own organization but status/push webhooks act on any repository's data - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-tenant Shipit deployment (one GitHub App/webhook secret per organization, via `Shipit.github_app_config`), the `WebhooksController#verify_signature` method selects which organization's secret to validate the HMAC signature against using a field taken directly from the attacker-controlled JSON body, while the event handlers act on a *different* attacker-controlled field from that same body to decide which repository/commit to mutate. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`verify_signature` computes `repository_owner` from the unauthenticated request body itself and uses it purely to pick which secret to verify the signature with: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization app config/secrets via `github_app_config`, confirming that in multi-org setups each organization has its own independent `webhook_secret`: [3](#0-2) 

Once the signature check passes, the raw payload is dispatched unmodified to handlers, and the handlers derive the *acted-upon* repository/commit from a separate field of the same body, `repository.full_name` (via `Handler#repository_name`) or, worse, an unscoped `sha`: [4](#0-3) 

`StatusHandler` never scopes by repository at all — it looks up commits globally by SHA and lets attacker-supplied `state`/`description`/`target_url`/`context` overwrite that commit's CI status: [5](#0-4) 

`PushHandler` and `CheckSuiteHandler` do use `stacks`, but that helper only checks `Repository.from_github_repo_name(repository_name)` — i.e., it trusts `repository.full_name` from the body, a field never covered by the signature-selection logic: [6](#0-5) [7](#0-6) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-upon repo) are two independent, attacker-supplied fields inside the same unauthenticated JSON body, an attacker who legitimately controls a GitHub App/organization onboarded onto this shared Shipit instance — and therefore knows their own `webhook_secret` — can craft a body where `repository.owner.login` = their own org (so the correct/known secret is used and the HMAC check passes) while `repository.full_name`/`sha` reference a victim organization's repository/commit. The equality that should hold — *organization whose secret validated the signature == organization whose repository/commit is mutated* — is broken.

### Impact Explanation
This is directly analogous to the reported `Locke.arbitraryCall()` issue: a check is performed against one piece of state (the caller's own known-good credential/org) while the action taken operates on unrelated state (an arbitrary target) that was never covered by that check. Here, an attacker with legitimate access to their own organization's webhook secret can:
- Use `StatusHandler` to inject a fabricated "success" (or any) CI status for an arbitrary commit SHA belonging to a victim's stack, since the handler applies no repository scoping at all — this can be used to satisfy Shipit's blocking/required status gating referenced in `Shipit::DeploySpec` and `app/models/shipit/commit.rb`, potentially enabling an unauthorized deploy of a commit that never actually passed CI.
- Use `PushHandler`/`CheckSuiteHandler` to force `stack.sync_github` or check-run refresh cycles on a victim's stacks by supplying `repository.full_name` for a repo the attacker does not own, causing unwanted state changes on the victim's stack outside their control.

This crosses the "cross-repository writes / unauthorized deploy" bar defined as Critical/High impact in scope.

### Likelihood Explanation
Requires the target Shipit instance to be configured in the multi-organization mode (`secrets.github` keyed by organization), which is a documented supported configuration (`github_app_config`), and requires the attacker to control at least one onboarded organization's own webhook secret — a credential they legitimately possess for their own tenant. No GitHub App private key, Shipit session, or API-client token is needed; the attacker only crafts and POSTs a raw JSON body with a valid HMAC using their own secret. This is a realistic scenario for any Shipit deployment shared across multiple, mutually-untrusted GitHub organizations.

### Recommendation
After signature verification, re-derive `repository_owner` from the same trusted field used to pick the verifying organization and require that all repository/commit references acted on by the handler (`repository.full_name`, `organization.login`) belong to that same verified organization before dispatching to handlers. `StatusHandler` in particular should scope its `Commit` lookup by the repository/stack that was authenticated, not by a bare SHA lookup across the entire installation.

### Proof of Concept
1. Deploy Shipit configured for multiple organizations, each with its own `webhook_secret` (per `github_app_config`).
2. As the owner of organization `attacker-org` (with known secret `S_attacker`), craft a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-existing-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(S_attacker, body)` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature using `S_attacker` (attacker's own known secret) against the crafted body — see [1](#0-0) .
5. `PushHandler#process` then resolves `stacks` via `repository.full_name = "victim-org/victim-repo"` [4](#0-3)  and triggers `stack.sync_github` on the victim's stack [6](#0-5)  — despite the signature only proving authorship by `attacker-org`, not by `victim-org`.
6. Equivalently, sending a `status` event with a victim commit's `sha` lets the attacker set an arbitrary CI status on that commit with no repository check at all [5](#0-4) .

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
