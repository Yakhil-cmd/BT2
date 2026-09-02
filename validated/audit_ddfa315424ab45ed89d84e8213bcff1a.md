### Title
Cross-tenant CI status forgery via webhook signature/payload binding mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to verify a webhook payload against using the `repository.owner.login` (or `organization.login`) field of the *attacker-controlled* JSON body, then dispatches the *same* body to handlers that act on a completely different field (`repository.full_name`, or — in the case of `status` events — no repository scoping at all, just the commit `sha`). In a multi-tenant Shipit deployment (explicitly supported, see `config/secrets.development.shopify.yml`), any tenant that legitimately owns one configured GitHub App/organization can forge a signature that Shipit accepts for their own org, while making the payload act on another tenant's repository/commit.

### Finding Description
`verify_signature` picks the verification secret purely from the payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization config/secret from `secrets.github`, supporting multiple GitHub Apps/organizations on one instance: [3](#0-2) 

Once the signature is verified against **organization A's** secret (`repository.owner.login == "org-a"`), the raw JSON body — fully attacker controlled — is dispatched to handlers with no re-validation that the rest of the payload is actually about org A: [4](#0-3) 

Most handlers resolve the target repository via `repository.full_name`, a field entirely independent of `repository.owner.login` used for signing: [5](#0-4) 

`StatusHandler` is worse: it doesn't even use `repository.full_name` — it looks up commits **globally, across all stacks/tenants**, by SHA alone: [6](#0-5) 

`Commit#create_status_from_github!` then writes the forged status and, on success/pending transitions, schedules merge processing for that (unrelated) stack: [7](#0-6) [8](#0-7) 

**Binding broken**: the organization whose secret authenticated the request (`repository.owner.login`) ≠ the repository/commit whose state is actually written (`repository.full_name` / bare `sha` lookup). This is exactly the "organization that authenticated versus the repository that is written" class called out in scope.

### Impact Explanation
An attacker who controls (or is the legitimate admin of) any single tenant/organization on a shared Shipit instance — i.e., someone who created their own GitHub App and thus knows their own `webhook_secret`, with no Shipit session, `ApiClient` token, or `GITHUB_TOKEN` — can:
- Sign an arbitrary JSON body with their own org's secret so `verify_signature` passes.
- Set `sha` to a commit SHA belonging to a victim organization's tracked repository (commit SHAs are public on GitHub and frequently visible via PR/commit URLs).
- Set `state: "success"`, `context: <required-check-name>` to inject a fabricated CI status for that commit.

Because `Status` creation drives `Commit#add_status`, which calls `stack.schedule_merges` on success/pending transitions, this can satisfy `ci.require` gating and trigger merge-queue processing / auto-merge for a stack belonging to an org the attacker has no access to — an unauthorized merge/deploy path. This matches the Critical impact bucket ("cross-repository writes... an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires the target Shipit instance to be configured in the multi-organization mode (`secrets.github` keyed by org, as documented/supported) and requires knowledge of any *one* tenant's `webhook_secret` — knowledge an org owner inherently has because they choose it themselves when creating their GitHub App. No compromise of Shipit's own credentials, sessions, or the victim tenant's secret is needed, so likelihood is moderate-to-high in any genuinely multi-tenant deployment.

### Recommendation
- Bind signature verification to the exact same repository/commit-scoping data the handler will use to act, not just to an org name pulled from an unrelated payload field.
- In `StatusHandler`, scope `Commit.where(sha:)` lookups to the repository named in the payload (and cross-check that repository's owner matches the org whose secret validated the signature) rather than searching globally by SHA.
- Consider stamping each webhook delivery with the resolved `GitHubApp`/organization and threading it through to every handler so all writes are scoped to that org's own repositories, rejecting payloads whose `repository.full_name` owner disagrees with `repository.owner.login`/`organization.login`.

### Proof of Concept
1. Configure Shipit with two orgs, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md` multi-org schema).
2. As the admin of `org-a` (attacker, no Shipit session/API token), compute `sha1=HMAC(webhook_secret_a, body)` for body:
```json
{
  "repository": {"owner": {"login": "org-a"}},
  "sha": "<sha of a commit tracked under org-b's stack>",
  "state": "success",
  "context": "<required-ci-context-for-org-b-stack>"
}
```
3. `POST /webhooks` with header `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` resolves `Shipit.github(organization: "org-a")` and verifies successfully.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the org-b commit (global lookup, no owner check), creating a forged "success" status and potentially triggering `schedule_merges` for org-b's stack — despite the request only being authenticated for org-a.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
