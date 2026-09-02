Confirmed: `docs/setup.md` explicitly documents "Webhook secret (optional)" and multi-organization setups where each org has its own independent `webhook_secret` [1](#0-0) , and `GitHubApp#verify_webhook_signature` skips verification entirely (`return true unless webhook_secret`) for any org configured without one [2](#0-1) . This is enough to establish the exploit precondition as a documented, supported configuration, not an undocumented misuse.

### Title
Webhook signature verified against attacker-chosen organization while status writes are unscoped by repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's secret to check the HMAC signature against using an attacker-supplied field in the JSON body (`repository.owner.login`, falling back to `organization.login`), not any value derived from an authenticated channel [3](#0-2) . Once verification passes, `StatusHandler#process` writes a new `Status` for every `Commit` matching the attacker-supplied `sha` field, with no scoping to the organization/repository that was used for verification at all [4](#0-3) . This breaks the equality binding: `organization whose secret verified the request == organization/repository whose data is written`.

### Finding Description
Shipit supports multiple GitHub organizations, each configured with its own `webhook_secret`, which is documented as **optional** per organization [1](#0-0) . When an organization has no `webhook_secret` configured, `GitHubApp#verify_webhook_signature` unconditionally returns `true`:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

`WebhooksController#verify_signature` picks *which* organization's `GitHubApp` (and therefore which secret, or lack thereof) to check against purely from the JSON payload itself:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

An unauthenticated attacker who knows (or guesses) the name of any organization hosted on this Shipit instance that has no `webhook_secret` set can set `repository.owner.login` to that org's name to pass `verify_signature` trivially — no secret or credential is required.

Once verification passes, the event handler is invoked with the full attacker-controlled JSON body. `StatusHandler#process` does not re-check that the commit being updated belongs to the organization that was used for verification — it looks up commits globally by `sha`:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

This directly persists attacker-supplied `state`, `description`, `target_url`, and `context` fields as a `Status` record via `Commit#create_status_from_github!` → `Status.replicate_from_github!` [6](#0-5) [7](#0-6) , for **any** commit sha across **any** stack/organization tracked by the Shipit instance, regardless of which organization "authenticated" the request.

`Commit#deployable?` gates whether a commit can be deployed on the latest status being `success` and not blocked: `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [8](#0-7) . By forging a `success` status for a target commit sha in a *different, properly-secured* organization's stack, an attacker can flip that commit's CI gate to deployable, and if that stack has `continuous_deployment` enabled the forged status will directly trigger an unauthorized deploy; otherwise it removes the CI safety check relied upon by a legitimate deploy request from a real user/API client.

This is the closest structural analog to the reported bug class: the report described a field (`NextClaimFrom`) that was updated using the wrong/unverified quantity of periods, letting a claim be authorized for a period it was never approved for. Here, the *authorization decision* (signature verification / which org is trusted) is bound to one payload field (`repository.owner.login`), while the *write target* (which commit/stack is modified) is bound to a completely different, unchecked field (`sha`) — the two are never checked for consistency, exactly the "equality that should hold but doesn't" pattern called out in the rules ("an organization that authenticated versus the repository that is written").

### Impact Explanation
This escalates into unauthorized deploy/rollback authorization: forging a CI status can make an arbitrary commit `deployable?` in a stack belonging to a fully-secured organization, which either triggers continuous deployment directly or removes the CI gate that a downstream deploy request depends on. This matches the "Critical - an unauthorized deploy" and "High - escalation ... unauthenticated ... task streams" categories in scope. No `ApiClient` token, session, or GitHub credential is required by the attacker — only knowledge that some organization on the instance lacks a `webhook_secret`, which is an explicitly documented, supported configuration (not a misconfiguration outside the engine's control).

### Likelihood Explanation
Requires: (1) the Shipit instance to host at least one organization without a configured `webhook_secret` (documented as optional/supported), and (2) a target commit sha in another organization's stack that the attacker wants to mark deployable (obtainable from public commit history/PRs on GitHub, or by simply predicting/observing recent shas). No other privileged access is needed. Likelihood is moderate-to-high in multi-org deployments where at least one org opts out of the webhook secret.

### Recommendation
Scope every webhook handler's side effects to the organization/repository that was actually verified, not to attacker-supplied payload fields:
- In `Handler#stacks`/`StatusHandler#process`, restrict the `Commit` lookup to stacks belonging to the repository/organization that was validated during `verify_signature` (pass the verified organization/repository down into the handler and filter `Commit.joins(:stack).where(stack: { ... })` accordingly).
- Do not allow signature verification for one org to authorize writes referencing data from another org; if an org has no `webhook_secret`, additionally validate that `repository.full_name`'s owner matches `repository_owner` before dispatching to handlers.

### Proof of Concept
1. Configure (or observe) a multi-org Shipit instance where `OrgWithoutSecret` has no `webhook_secret` set, per the documented "Using Multiple Github Applications" setup [1](#0-0) .
2. `POST /webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "OrgWithoutSecret" }, "full_name": "OrgWithoutSecret/whatever" },
  "sha": "<sha of target commit in VictimOrg/victim-repo>",
  "state": "success",
  "context": "ci/forged",
  "description": "forged",
  "target_url": "https://example.com"
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgWithoutSecret")`, whose `verify_webhook_signature` returns `true` unconditionally [2](#0-1) .
4. `StatusHandler#process` finds the commit by `sha` regardless of organization and creates a `success` `Status` on it [4](#0-3) , making it `deployable?` in `VictimOrg/victim-repo`'s stack even though no valid signature for `VictimOrg` was ever presented.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
