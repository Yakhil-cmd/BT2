### Title
Webhook signature verified against payload's claimed organization, but downstream handlers act on payload's claimed repository full name — allowing cross-organization/repository event forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify a signature against based on `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON payload. Once the signature check passes, the actual repository that is acted upon by the event handlers (e.g. `PushHandler`) is derived from a *different* payload field, `repository.full_name`, which is never cross-checked against the organization used for signature verification. An attacker who controls a legitimate GitHub App installation (and therefore its own configured `webhook_secret`) for Organization A can sign a payload with their own secret while setting `repository.full_name` to point at a repository owned by an unrelated Organization B, causing Shipit to act on Organization B's `Stack`.

### Finding Description
`verify_signature` picks the "authenticating organization" purely from payload content: [1](#0-0) [2](#0-1) 

The signature is verified using `Shipit.github(organization: repository_owner)`, i.e., whichever GitHub App config matches the `repository.owner.login` (or `organization.login`) claimed in the JSON body: [3](#0-2) 

After the signature passes, every handler determines the repository to act on from a *separate* field, `repository.full_name`, with no relation enforced to `repository.owner.login` used above: [4](#0-3) 

`Repository.from_github_repo_name` simply splits this attacker-controlled string into owner/name and looks up whatever `Repository`/`Stack` matches it: [5](#0-4) 

`PushHandler` (and other handlers) then act on the stacks resolved from that mismatched field, e.g. triggering a GitHub sync: [6](#0-5) 

This is structurally identical to the wXTZ bug class: a check (signature/ownership validation) is performed against one field/entity (`repository.owner.login`, the organization whose secret is used), while the actual action is executed against a different, unchecked field/entity (`repository.full_name`, the repository actually written to). The binding that should hold — "the organization that authenticated == the repository that is written" — is never enforced.

### Impact Explanation
In a multi-tenant Shipit deployment configured with multiple GitHub Apps (one per organization, as documented in `docs/setup.md` and `config/secrets.development.example.yml`'s multi-org example), any organization admin who legitimately knows their *own* app's `webhook_secret` can forge a webhook whose `repository.full_name` names a Stack that belongs to a completely different, unrelated organization. Because `PushHandler` uses only `full_name` to resolve stacks and then calls `stack.sync_github`, this allows an attacker with no relationship to Organization B to trigger internal state-changing operations (`GithubSyncJob`) against Organization B's `Stack`, crossing an organizational trust boundary the signature check was supposed to enforce. This matches the "cross-repository writes" / unauthorized action impact bucket.

### Likelihood Explanation
Likelihood is limited to deployments that configure more than one GitHub App/organization in `secrets.yml` (the documented multi-org configuration). In that configuration, every organization that is onboarded already knows its own `webhook_secret` by design (they configured their own GitHub App), so no credential theft is required — only crafting a POST to `/webhooks` with a payload whose `repository.owner.login` matches their own org (to pass the secret lookup/signature check) but whose `repository.full_name` names another organization's repository.

### Recommendation
**Short term:** After `verify_signature` succeeds, assert that `repository.owner.login` (the field used to select the signing organization) is consistent with the owner portion of `repository.full_name` (the field used by handlers to resolve `Stack`/`Repository`). Reject the webhook if they diverge.

**Long term:** Avoid deriving trust-relevant identifiers (which organization signed vs. which repository is mutated) from two independent, unrelated payload fields. Compute the repository/organization identity once, verify the signature against it, and reuse that single verified value throughout all downstream handlers instead of re-reading `full_name` independently in `Handler#repository_name`.

### Proof of Concept
1. Shipit is configured with two GitHub Apps, one for `OrgA` and one for `OrgB` (see multi-org example in `config/secrets.development.example.yml`), each with its own `webhook_secret`.
2. OrgA's administrator (an attacker with no access to OrgB) crafts a JSON payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<any sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
3. They compute `X-Hub-Signature: sha1=HMAC(webhook_secret_of_OrgA, payload)` using their own legitimately known `webhook_secret`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature check passes (attacker signed with OrgA's own secret).
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/target-repo")`, matching Organization B's actual repository/stack, and calls `stack.sync_github(expected_head_sha: params.after)` — an action on Organization B's stack triggered solely using Organization A's credentials.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
