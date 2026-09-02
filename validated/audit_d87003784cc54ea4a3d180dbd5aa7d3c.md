### Title
Cross-organization webhook forgery via mismatched signature-verification identity and repository-action identity - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate a webhook against using `repository.owner.login` (or `organization.login`), but the event handlers that act on the payload (`Handler#repository_name`, used by `PushHandler`, and `StatusHandler`, which doesn't scope by repository at all) key off a different, independently-attacker-controlled field: `repository.full_name` / a bare commit `sha`. Because the HMAC signature covers the raw request body as a whole, anyone who legitimately knows the `webhook_secret` for *one* organization configured in this Shipit instance can craft a validly-signed payload whose `repository.owner.login` matches that known organization (so signature verification passes) while `repository.full_name` (or the `sha` in a `status` event) references a completely different, victim organization's stack/commit.

### Finding Description
`verify_signature` picks the app config by owner login taken straight from the untrusted payload, then validates the *entire* raw body against that org's secret: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` just HMACs the whole raw message with whichever org's secret was selected: [3](#0-2) 

Once verification passes, the controller dispatches to handlers with the full, attacker-controlled JSON, and those handlers derive the *target* repository/commit from a different field than the one used for signature-org selection: [4](#0-3) [5](#0-4) 

`StatusHandler` is even weaker — it never checks the repository at all, and updates *any* commit anywhere in the instance that happens to share the forged `sha`: [6](#0-5) 

This breaks the intended binding: `organization that authenticated == repository that is written`. Instead, the engine trusts `repository.owner.login` for authentication but `repository.full_name`/`sha` for authorization — two fields inside the same signed body that are never cross-checked against each other. This mirrors the reported `ArroToken.transferAnyERC20Token` flaw, where the function authenticated against one address (`msg.sender`/owner) but acted on tokens belonging to a different, attacker-chosen address (the stray token's own balance) instead of the intended target.

Docs confirm this is a supported, documented multi-tenant configuration where distinct organizations each have their own `webhook_secret`, `app_id`, etc., under one Shipit deployment: [7](#0-6) 

### Impact Explanation
An attacker who is a legitimate but unprivileged member/admin of *any one* GitHub organization configured in a multi-org Shipit instance (i.e., someone who created/knows the `webhook_secret` of their own org's app, with zero access to the victim org's repos) can:
- Forge a `push` event: sign it with their own org's secret, set `repository.owner.login` to their own org (to pass verification) and `repository.full_name` to `victim-org/victim-repo`, causing `PushHandler` to trigger `stack.sync_github` for the victim stack.
- Forge a `status` event: because `StatusHandler` never checks repository ownership, sign an event with their own org's secret referencing an arbitrary victim commit `sha` and set `state: "success"`. `Commit#create_status_from_github!` will record this as a real CI status, which feeds directly into `Commit#deployable?` (`success? && !blocked?`) and `Commit#schedule_continuous_delivery`, potentially causing an **unauthorized deploy** of a commit that never actually passed the victim's real CI, or unblocking a merge queue (`stack.schedule_merges`).

This is a cross-organization confused-deputy that can escalate to an unauthorized deploy/merge on repositories the attacker has no access to — matching the Critical/High impact bar ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires only that: (1) the Shipit deployment is configured for multiple GitHub organizations (a documented, supported configuration), and (2) the attacker controls/knows the `webhook_secret` for at least one of those organizations (e.g., they set up their own org's GitHub App integration). No access to the victim org, no Shipit session, and no API token are needed — only the ability to POST to the public `/webhooks` endpoint with a forged, but validly-signed-for-their-own-org, payload. Note: this only affects deployments with more than one organization configured; single-organization deployments are not exposed by this specific analog, and the exact scope of impact for `PushHandler` (which merely re-syncs commits from GitHub, not deploy directly) is less severe than the `StatusHandler` path, which can directly flip `deployable?`.

### Recommendation
Bind the field used to select the verification secret to the field used for authorization decisions:
- In `WebhooksController#verify_signature`, after selecting the org via `repository_owner`, also assert that `params.dig('repository', 'full_name')` (or `params.dig('organization', 'login')`) belongs to that same organization before dispatching to handlers.
- In `Handlers::StatusHandler#process`, scope the `Commit` lookup by the stack/repository derived from the verified organization (reuse `Handler#stacks`/`#repository_name` and require it match `repository_owner`), instead of a bare, unscoped `Commit.where(sha: params.sha)`.
- More generally, treat `repository.owner.login` and `repository.full_name` as needing to agree, and reject the webhook (422) if they don't correspond to the same organization used for signature verification.

### Proof of Concept
1. Configure Shipit with two organizations, `AttackerOrg` and `VictimOrg`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`'s multi-org example).
2. As a member of `AttackerOrg` (unprivileged w.r.t. `VictimOrg`), craft a `status` webhook payload:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/attacker-forged",
     "repository": { "owner": { "login": "AttackerOrg" }, "full_name": "AttackerOrg/anything" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(AttackerOrg_webhook_secret, raw_body)>` and `X-Github-Event: status`, then POST to `/webhooks`.
4. `verify_signature` resolves `repository_owner` = `AttackerOrg`, fetches `Shipit.github(organization: 'AttackerOrg')`, and the signature validates successfully since the attacker knows that secret.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim commit anywhere in the instance — and calls `create_status_from_github!`, marking it `success`, which can flip `Commit#deployable?` and trigger `schedule_continuous_delivery`/`schedule_merges` for `VictimOrg`'s stack, none of which the attacker had any authorization over.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
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
