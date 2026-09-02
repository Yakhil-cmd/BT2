### Title
Multi-org webhook signature verified against organization A's secret while the handler acts on repository B named in the same unsigned-binding payload field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In the multi-organization GitHub App configuration, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC against using `repository_owner`, taken from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). Once the signature check passes, the event is dispatched to handlers that instead resolve the *acted-upon* repository/stack from a different, independently-controlled payload field: `payload.dig('repository', 'full_name')` in `Shipit::Webhooks::Handlers::Handler#repository_name`. Because HMAC verification covers the *entire* raw request body as bytes (not a semantically-bound "this signature is only valid for org X's repos" guarantee), a party who legitimately controls a webhook secret for one configured organization (e.g., installs the Shipit GitHub App on their own organization "A") can compute a valid signature for an arbitrary JSON body, including a `repository.full_name` that names a different, victim-tracked repository "B/repo" under organization B. The engine will accept this payload as authentic (verified with org A's secret) and then dispatch push/status/check_suite/commit_status/merge/deployable_status events against stack(s) belonging to `B/repo`.

### Finding Description
- `WebhooksController#verify_signature` picks the GitHub App/secret purely from `repository_owner`, computed from the payload itself: [1](#0-0) [2](#0-1) 
- `Shipit.github(organization:)` resolves per-organization app config/secret via `github_app_config`, confirming multi-tenant orgs each have their own independent `webhook_secret`: [3](#0-2) 
- Once `verified` is true, the raw payload is dispatched to handlers without any re-check that the acted-upon repository belongs to the same organization whose secret validated the signature: [4](#0-3) 
- All handlers derive the repository/stack to act on from `payload.dig('repository', 'full_name')`, which is a completely separate JSON key from `repository.owner.login` used for secret selection — both are attacker-suppliable fields inside the same signed byte-string, and the signature (an HMAC over raw bytes) does not enforce any relationship between them: [5](#0-4) [6](#0-5) 

The trust binding broken is: **organization authenticated (`repository.owner.login` used to select the webhook secret) == repository that is written (`repository.full_name` used by the handler to find and mutate the stack)**. The signature computation happening inside `Shipit::GitHubApp#verify_webhook_signature` only guarantees the *bytes* weren't tampered with relative to *some* known secret — it says nothing about which organization's repository the payload is allowed to reference: [7](#0-6) 

An attacker who is a legitimate GitHub organization admin/owner for an organization "A" that has installed the Shipit GitHub App (and therefore knows/controls org A's `webhook_secret`, e.g. by configuring the app in their own org settings and receiving delivery secrets, or in cases where webhook secrets are shared/blank across orgs) can craft an arbitrary POST body: set `repository.owner.login = "A"` (so `verify_signature` picks org A's secret, which the attacker knows) but set `repository.full_name = "B/victim-repo"` (a completely unrelated, tracked repository belonging to org B). Since the HMAC signature is computed over the raw JSON bytes using org A's secret — which the attacker has legitimately — the forged payload passes `verify_signature`, and the `push`, `status`, `check_suite`, `commit_status`, `merge`, `deployable_status`, or `membership` handler then runs against Stack(s)/Repository `B/victim-repo` using attacker-chosen data (e.g. injecting a forged commit into the git history of `B`'s stacks via `GithubSyncJob`, forging a commit status via the `status` handler, or forging check-suite results via `check_suite`).

### Impact Explanation
This crosses the "unauthorized deploy/rollback/merge" and "cross-repository writes" bar in the rules: an attacker with legitimate control of one organization's webhook secret can forge events attributed to and acted upon a completely different, victim-owned repository/stack that they have no access to. Depending on which event is forged:
- `push` → `GithubSyncJob` will fetch and append commits reachable from a forged `after` SHA into the victim stack's undeployed queue, potentially unlocking/deploying attacker-influenced commits.
- `status`/`check_suite`/`commit_status` → forged CI green checks on the victim stack's commits, bypassing deployability gates that gate the ship button.
- `merge_status`/`deployable_status` → can flip merge/deployability state used to authorize merges.

This is a direct analog of the reported bug class: the field the trust decision is made on (`repository.owner.login`, akin to the loan's max-liquidity calc) is disjoint from the field actually acted upon (`repository.full_name`, akin to the collateral actually liquidated), and nothing enforces they must match.

### Likelihood Explanation
Requires the deployment to be configured with the multi-organization GitHub config format (multiple orgs under `secrets.github`), and requires the attacker to control at least one configured organization's webhook secret — attainable by any GitHub org owner who is permitted to install/onboard the Shipit App for their own org in a multi-tenant Shipit deployment, or in any setup where webhook secrets are not unique per organization (e.g., left blank/shared, since `verify_webhook_signature` returns `true` for a `nil` secret). No repository write access, `ApiClient` token, or session for the victim repository is needed — only knowledge of one org's webhook secret, which the rules permit as an unprivileged-attacker capability relative to the victim repository.

### Recommendation
After signature verification, re-derive `repository_owner` from the payload and require it to match the organization that was actually used to verify the signature (or, more strongly, require `payload.dig('repository','full_name')`'s owner segment to equal the org whose secret validated the signature) before dispatching to handlers. Reject the webhook if these do not match.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `orgA` (attacker's own org, webhook_secret known to attacker) and `orgB` (victim org, tracked stack `orgB/victim-repo`).
2. Attacker crafts JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha reachable from a forged history>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(orgA_webhook_secret, body)>` using the secret they legitimately know for `orgA`.
4. POST to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA")` and validates the signature successfully (org A's secret matches).
6. `PushHandler#process` resolves `stacks` via `repository_name` = `orgB/victim-repo` and dispatches `sync_github` on the victim's stack, entirely bypassing the fact that the signature was never generated by, nor known to, org B.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
