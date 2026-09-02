### Title
Webhook Organization Confused Deputy Allows Cross-Tenant Commit Status Forgery and Unauthorized Deploys - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization secret to validate an inbound webhook's HMAC against by reading an **attacker-controlled field from the very payload being verified**, rather than from any externally-authenticated channel. In a multi-tenant Shipit deployment (multiple organizations, each with its own `app_id`/`webhook_secret` under `secrets.github`), this breaks the binding between "the organization whose secret authenticated the request" and "the repository the request is allowed to mutate," letting an attacker who controls one tenant's webhook secret forge events that act on a different tenant's data — most severely, forging a passing CI status for an arbitrary commit SHA anywhere in the instance.

### Finding Description
`verify_signature` derives the org used for HMAC verification purely from the JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves a distinct `GitHubApp` (distinct `app_id`, `private_key`, and crucially `webhook_secret`) per organization key configured under `secrets.github`: [3](#0-2) 

So the equality the engine implicitly relies on is:
`organization whose webhook_secret produced a valid HMAC == organization that owns the repository/commit the handler subsequently mutates`

This equality does not hold: the field used to select the verification secret (`repository.owner.login` / `organization.login`) and the field handlers use to decide *what to act on* are both attacker-supplied JSON keys inside the same raw body, and nothing forces them to refer to the same tenant. A forger who is a legitimate GitHub App administrator/installer for **their own** organization (Org A, tenant of this same shared Shipit instance) knows Org A's `webhook_secret`. They can:
1. Set `repository.owner.login` (or `organization.login`) to `"org-a"` so `verify_signature` selects Org A's `GitHubApp` and its secret.
2. Compute a valid `X-Hub-Signature` over the full raw body using Org A's secret (which they legitimately possess).
3. Set the event-specific payload fields consumed by handlers to reference a *different* victim tenant, e.g. for the `status` event, an arbitrary `sha` belonging to Org B's repository.

`StatusHandler` then looks up the target purely by SHA, with **no scoping to any repository or organization at all**: [4](#0-3) 

Other handlers (`PushHandler`, `PullRequest::*Handler`) scope by `repository.full_name` via the shared `Handler` base class, which is likewise just another attacker-controlled JSON field independent of the field used for signature-secret selection: [5](#0-4) [6](#0-5) 

The controller test setup even documents that `repository.full_name` is freely editable independent of the org used for signature checks: [7](#0-6) 

### Impact Explanation
This is a cross-repository/cross-tenant write achieved purely through a forged, signature-"valid" webhook — the impact category is "cross-repository writes" / "an unauthorized deploy." Concretely:
- `status` event: `StatusHandler` (unscoped by repo) lets an Org A-signed webhook fabricate a `success` CI status for any commit SHA on any stack tracked by the whole instance, including stacks belonging to Org B. Shipit's deploy readiness/merge-queue gating (`ci.require`, `commit.deployable?`) is driven by these `Status` records, so an attacker can manufacture the appearance of green CI for a commit that never actually passed real checks, enabling an **unauthorized deploy** of that commit in Org B's stack.
- `push`/`pull_request`/`membership` events: scoped by `repository.full_name`, still let an Org A-authenticated request drive `GithubSyncJob`, PR review-stack provisioning/unprovisioning, or `Team`/`Membership` creation/deletion for Org B's repositories/teams, none of which the forger's own organization's webhook secret should have authority over.

### Likelihood Explanation
Requires only that the attacker be able to configure/observe the webhook secret for *any one* organization/tenant served by the same self-hosted Shipit instance (a normal, unprivileged action for someone administering their own GitHub App installation on a shared Shipit deployment), and that the instance track at least one other organization's repositories. No GitHub write access, `ApiClient` token, session, or private key for the victim org is needed — only the forger's own tenant's webhook secret and knowledge of a target commit SHA/repository full name (both easily discoverable from public GitHub data).

### Recommendation
Bind the verified organization to the object being mutated instead of trusting body-supplied fields for routing:
- After successfully verifying with a given organization's secret, require that `repository.owner.login` (or `organization.login`) match the organization actually owning the `Repository`/`Stack`/`Commit` being acted on, and reject otherwise.
- In `StatusHandler`, scope the `Commit.where(sha:)` lookup to commits whose stack's repository belongs to the verified organization, mirroring the scoping already used in `Handler#stacks`/`#repository_name`.
- More generally, do not let any single JSON field chosen from the unauthenticated request body determine which secret is used to authenticate that same request; instead validate against every configured organization's secret to find a match and then check the resulting owning organization equals the org whose secret matched, rather than the reverse.

### Proof of Concept
1. Attacker administers `org-a`, a legitimate tenant configured under `secrets.github.org_a` on a shared self-hosted Shipit instance, and knows `org_a`'s `webhook_secret` (they set it up when installing their GitHub App).
2. Attacker crafts a `status` event JSON body:
   ```json
   {
     "sha": "<victim-org-b-commit-sha>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "org-a" } }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org_a_webhook_secret, raw_body)>`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")`, whose `webhook_secret` matches the attacker's HMAC — verification passes (see `verify_webhook_signature`): [8](#0-7) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — because it is unscoped, it matches the victim `org-b` commit and creates a fabricated "success" status for it, regardless of the fact that the request was authenticated only for `org-a`.
6. This falsified status can satisfy `ci.require` gating for `org-b`'s stack, permitting a deploy of that commit that Shipit would otherwise have blocked.

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

**File:** test/controllers/webhooks_controller_test.rb (L12-21)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
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
