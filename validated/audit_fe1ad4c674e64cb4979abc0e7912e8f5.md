### Title
Cross-Organization Webhook Signature Confusion Allows Forged CI Status on Any Stack's Commits, Bypassing Deploy Gating - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The Sherlock report describes a binding break where a value used to *compute* an on-chain threshold (total votes at proposal creation) can be manipulated independently of the value used to *gate* the action (self-delegated votes at vote time). The same class of bug exists in Shipit's webhook pipeline: the value used to *authenticate* an incoming webhook (`repository.owner.login`, used to pick which GitHub App/organization's `webhook_secret` verifies the signature) is never re-checked against the value used to *act* on data (the commit's owning stack/repository). For the `status` webhook, the acting logic doesn't even use the repository at all — it matches purely by commit SHA across the entire Shipit installation.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the `webhook_secret` used to validate `X-Hub-Signature`) using a value pulled straight from the untrusted JSON body: [1](#0-0) [2](#0-1) 

Shipit explicitly supports configuring **multiple GitHub organizations**, each with its own `webhook_secret`, looked up by name: [3](#0-2) 
This is a documented, first-class deployment pattern (see `config/secrets.development.shopify.yml` and the "multiple Github applications for different Github organizations" section of `docs/setup.md`).

Once the signature is verified against the org named in `repository.owner.login`, the event is dispatched to handlers that resolve *what to act on* independently, using different payload fields. The base `Handler` normally scopes to a `Repository` via `repository.full_name`: [4](#0-3) 

However, `StatusHandler` — which drives GitHub Status/CI state used to gate deploys — does not use repository scoping at all. It matches commits purely by SHA across the whole database: [5](#0-4) 

The equality that should hold is:
`organization whose webhook_secret verified the signature == organization owning the repository/commit that gets mutated`

Instead, in a multi-org Shipit instance, an attacker who legitimately controls one onboarded GitHub organization (and therefore knows that org's own `webhook_secret`, which they configured or received when they were onboarded) can:
1. Craft a `status` event payload with `repository.owner.login` = their own org (so `verify_signature` looks up and validates against *their own* org's secret — signature check passes).
2. Set `sha` to the SHA of a commit belonging to a **different** onboarded org's stack (SHAs are content-addressed Git hashes, typically visible on GitHub, in commit links, PR pages, or CI dashboards).
3. Set `state: "success"` (and matching `context`) for a status check that the victim stack's `shipit.yml` lists under `ci.require`/`ci.blocking`.

Because `Commit.where(sha:)` is global and unscoped by repository/organization, this forges a passing CI status on the victim stack's commit, even though the signature was never validated by the victim organization's secret.

### Impact Explanation
`deployable?` and the `ci.require`/`ci.blocking` checks defined in `shipit.yml` gate whether a commit can be deployed (or automatically continuous-deployed): [6](#0-5) 
By forging a "success" status via a cross-tenant signature-confused webhook, an attacker who only controls a low-privilege GitHub organization/app installation on a shared/multi-tenant Shipit instance can make a victim organization's blocked or failing commit appear deployable, resulting in an **unauthorized deploy** of another organization's stack — this maps directly to the Critical impact category (unauthorized deploy) since it lets an attacker who has no Shipit account, no `ApiClient` token, and no access to the victim org's actual webhook secret still cause state changes (and downstream deploy actions) against the victim's repository.

### Likelihood Explanation
This requires:
- A Shipit instance configured for multiple GitHub organizations (a documented, supported configuration, not a misconfiguration), and
- The attacker to legitimately administer (or have App-installation access to) at least one of the onboarded organizations, and
- Knowledge of a target commit SHA belonging to another onboarded org (typically public via GitHub UI/API, PR pages, or the Shipit UI itself if it exposes commit SHAs).

No Shipit session, `ApiClient` token, GitHub App private key, or the victim's `webhook_secret` is required — only the attacker's own, legitimately-possessed org secret. This satisfies the "unprivileged attacker" and "break a deployment-trust binding" criteria (organization authenticated vs. repository/commit written).

### Recommendation
- In `StatusHandler#process` (and any other handler that doesn't scope through `stacks`), scope the `Commit` lookup by the `Repository` derived from `payload.dig('repository', 'full_name')` (the same field the base `Handler` already uses for `stacks`), not merely by `sha`.
- More generally, after `verify_signature` succeeds, assert that the organization used to select the `webhook_secret` (`repository.owner.login`) matches the owner encoded in `repository.full_name` before dispatching to handlers, so a payload can't claim one org for authentication and a different org's resource for mutation.

### Proof of Concept
Conceptual sequence (requires a multi-org Shipit deployment where the attacker administers "attacker-org" and the victim stack belongs to "victim-org/victim-repo"):
1. Attacker obtains their own org's `webhook_secret` for "attacker-org" (legitimately, as configured in `secrets.github.attacker-org.webhook_secret`).
2. Attacker crafts a `status` event JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Attacker signs the raw body with `attacker-org`'s `webhook_secret` (HMAC-SHA1) and sends it to `POST /webhooks` with header `X-Github-Event: status` and the computed `X-Hub-Signature`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies successfully (their own secret matches). [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (regardless of `attacker-org` vs `victim-org`), and calls `commit.create_status_from_github!(params)`, marking it `success` for `victim-org`'s required CI context. [5](#0-4) 
6. The victim stack's `deployable?`/`required_statuses` check now passes for that commit, permitting a deploy that should have been blocked.

Note: I was not able to execute this end-to-end in a live environment (no filesystem/terminal access in this mode); the analysis is based on static review of the cited files. If further confirmation is needed (e.g., exact HMAC test vectors or a full request replay), a Devin session with repository and terminal access would be needed to reproduce and validate the forged webhook end-to-end.

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

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```
