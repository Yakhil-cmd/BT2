### Title
Webhook signature verification binds to `repository.owner.login`/`organization.login` while all webhook handlers act on the untrusted `repository.full_name` field, allowing cross-organization/cross-repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the HMAC signature against using `repository_owner`, a value extracted from the *same untrusted payload* it is supposed to authenticate. Once the signature check passes, the raw `params` hash (including the attacker-controlled `repository.full_name`) is handed unmodified to every registered webhook handler, which resolve the target `Repository`/`Stack` via `full_name`, not via the field that was actually verified. This breaks the trust binding `organization that authenticated == repository that is written`.

### Finding Description
`verify_signature` computes the signing organization purely from payload content: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), and `Shipit.github(organization: repository_owner)` is used to pick the webhook secret for HMAC verification in `verify_webhook_signature`: [3](#0-2) 

After the signature check succeeds, the controller dispatches the entire unmodified `params` payload to handlers: [4](#0-3) 

Every handler resolves the affected `Stack`/`Repository` using a *different* field of the same payload — `repository.full_name` — via the base `Handler` class: [5](#0-4) [6](#0-5) 

For example, `PushHandler` triggers `stack.sync_github(expected_head_sha: params.after)` on whatever stacks belong to the repository named in `repository.full_name`: [7](#0-6) 

`repository.owner.login` (used to pick the signing secret) and `repository.full_name` (used to pick the acted-upon repository) are independent, attacker-controlled JSON fields with no cross-validation that they refer to the same repository or organization. An attacker who administers *any* GitHub organization/repository that is itself onboarded into this Shipit instance (and therefore knows/can trigger that org's legitimate webhook secret through their own repo's real GitHub webhook) can craft a JSON body where `repository.owner.login` equals their own org (so the HMAC check passes using their org's real secret) while `repository.full_name` names a repository belonging to a completely different organization that is also tracked by this Shipit instance. The request will pass signature verification and then act on the victim organization's `Stack`.

### Impact Explanation
This is a cross-repository write: an org that legitimately authenticates a webhook can cause handlers to mutate state (sync GitHub status/commits, potentially trigger merge/deploy-adjacent side effects) for stacks/repositories belonging to a wholly unrelated organization it does not control, purely because the signature-selection field and the action-target field are never bound together. This matches the required Critical impact category of cross-repository writes triggered without appropriate authorization.

### Likelihood Explanation
Exploitation requires the attacker to control a legitimate GitHub organization/repository that is already configured in this Shipit instance (so they can drive a validly-signed webhook delivery, or replicate the HMAC using a secret they legitimately possess for their own org). This is plausible in any Shipit deployment tracking multiple, mutually distrusting organizations/tenants — exactly the multi-org configuration the codebase explicitly supports (`Shipit.github(organization: ...)`, `GithubOrganizationUnknown`). No GitHub App private key, `webhook_secret` of the victim, or Shipit session/API token is needed — only the attacker's own onboarded org's secret, which they legitimately hold.

### Recommendation
Bind the two payload fields together before dispatching to handlers: after verifying the signature for `repository_owner`, assert that `payload.dig('repository', 'full_name')` (and any other repository identifiers used later, e.g. in `organization`/`membership` events) belongs to that same verified owner, or resolve the target strictly from the verified owner rather than from an independently-read `full_name` field. Reject the webhook if the two disagree.

### Proof of Concept
1. Onboard organization `attacker-org` into Shipit legitimately (or use one you already administer) and note that Shipit tracks its real webhook secret `S_attacker`.
2. Shipit also tracks a `victim-org/victim-repo` stack belonging to a different, unrelated org.
3. Craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(S_attacker, body)>` using the legitimately-known `attacker-org` secret.
5. POST to `/webhooks`. `verify_signature` resolves `repository_owner` = `attacker-org`, verifies successfully against `S_attacker`.
6. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack, even though the signature never authenticated anything about `victim-org`.

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
