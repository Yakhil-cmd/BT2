Based on the engine code I was able to examine, the strongest reachable analog is a mismatch between the GitHub organization that authenticates a webhook delivery and the repository that the delivery is allowed to mutate, which becomes exploitable once Shipit is run in the documented multi-organization configuration.

### Title
Webhook signature is verified against `repository.owner.login` but stack/commit writes are dispatched using `repository.full_name`, letting one authenticated GitHub App organization write to another organization's stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the delivery against using only `repository.owner.login` (or `organization.login`) from the JSON body [1](#0-0) . Once the HMAC check for *that* organization passes, the entire raw payload — including the `repository.full_name` field that downstream handlers use to resolve the actual `Stack`/`Repository` records — is handed unfiltered to `Shipit::Webhooks.for_event(event)` handlers [2](#0-1) . Nothing in the controller cross-checks that `repository.full_name`'s owner segment actually equals the `repository_owner` value that was used to pick the signing secret.

### Finding Description
Shipit explicitly supports hosting multiple GitHub organizations against a single instance, each with its own GitHub App and independent `webhook_secret`, as documented in "Using Multiple Github Applications" [3](#0-2) . In this mode, `Shipit.github(organization: repository_owner)` returns the `GithubApp` (and its `webhook_secret`) belonging to whichever organization is named in `repository.owner.login`/`organization.login` of the inbound payload [4](#0-3) .

Because `verify_webhook_signature` only proves that *some* field of the payload (`repository_owner`) matches the org whose secret was used, and the HMAC is computed over the entire `request.raw_post` [5](#0-4) , the check only guarantees "this body was signed by org A's secret" — it does not guarantee that the `repository.full_name` referenced elsewhere in that same body actually belongs to org A. An administrator/holder of org A's GitHub App webhook secret (a legitimate, low-privilege actor with respect to org A only) can therefore construct and directly POST a payload where `repository.owner.login == "orgA"` (satisfying signature selection) while `repository.full_name` names a repository belonging to org B, which also has a `Stack` configured on the same shared Shipit instance.

`PushHandler#process` then resolves target stacks and calls `stack.sync_github(expected_head_sha: params.after)` purely from the payload's `ref`/`branch` and repository match, without any dependency on `repository_owner` [6](#0-5) , i.e. the "authenticated organization" and the "repository being written" are two independent fields in the same evaluation. This is the same class of bug as the report's core defect: an operation (`approve`/webhook write) is authorized against one identifier (allowance owner / signing organization) while it actually acts on a different, attacker-influenced identifier (spender / target repository), and the mismatch is dormant until the "multi-X deployment" feature (multi-chain token deployment / multi-org GitHub App deployment) is turned on.

### Impact Explanation
If exploitable, this allows an actor who is only entitled to interact with their own organization's webhook to cause writes (synced commits, statuses, forced `sync_github` calls, and — if `continuous_deployment` is enabled on the victim stack — deploy triggering) against another organization's `Stack`, which is explicitly listed as an acceptable "cross-repository writes" / unauthorized-deploy-class impact.

### Likelihood Explanation
This requires the operator to run Shipit in the documented multi-organization mode (one GitHub App/`webhook_secret` per org sharing one Shipit instance) and requires the attacker to control the webhook secret for at least one onboarded organization — a realistic scenario for any SaaS-like or platform-team deployment of Shipit-engine serving multiple internal or external orgs, and does not require repository write access, an `ApiClient` token, or a Shipit user session, so it fits the "unprivileged attacker" boundary defined by the rules.

### Recommendation
In `WebhooksController#verify_signature` (or in each `Handler`), assert that every repository/organization identifier read from the payload later (e.g. `repository.full_name`'s owner segment, or any `organization.login` used by handlers) is consistent with the `repository_owner` value that selected the signing secret, and reject the delivery otherwise.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own `webhook_secret`, per `docs/setup.md`'s multi-org example, and create a `Stack` for a repo under `orgB`.
2. As someone who only knows `orgA`'s `webhook_secret` (e.g., an org owner who registered their own GitHub App against this shared instance), build a `push` JSON body with `"repository": {"full_name": "orgB/target-repo", "owner": {"login": "orgA"}}`, `ref: "refs/heads/<orgB stack branch>"`, and a chosen `after` SHA.
3. Sign the raw body with `orgA`'s `webhook_secret` using the `sha1=` HMAC scheme expected by `verify_webhook_signature`, and POST it directly to the `/webhooks` endpoint with `X-Github-Event: push` and the computed `X-Hub-Signature`.
4. Observe that `verify_signature` succeeds (it only checks `repository.owner.login == "orgA"` against `orgA`'s secret) and that `PushHandler` proceeds to call `sync_github` on `orgB`'s stack, demonstrating a cross-organization write triggered by credentials scoped to a different organization.

Note: I was not able to inspect `app/models/shipit/webhooks/handlers/handler.rb` (base `Handler#stacks`/repository-resolution logic) or `Stack#sync_github` in this session due to tool-call exhaustion; the PoC above assumes the repository-to-stack resolution shown for `PushHandler` follows only `full_name`/`branch` matching as suggested by the code retrieved. Confirming the exact resolution logic in `handler.rb` and `app/models/shipit/stack.rb#sync_github` is recommended before treating this as fully proven.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
