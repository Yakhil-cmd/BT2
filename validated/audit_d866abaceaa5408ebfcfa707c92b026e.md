### Title
No vulnerability — logged signature is attacker-supplied, not the server secret - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The `verify_signature` before_action logs `request.headers['X-Hub-Signature']` verbatim on every webhook request, but this value is the caller-supplied header (the attacker's own guess/forgery attempt), never the server's `webhook_secret` or the HMAC computed from it. No secret leakage occurs.

### Finding Description
The binding under test is: `logged_signature == request.headers['X-Hub-Signature']` (attacker input) versus the claimed leak `logged_signature == Shipit.github_app(...).webhook_secret` (server secret). Tracing the code: [1](#0-0) , `verify_signature` calls `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)` and separately logs `"signature=#{request.headers['X-Hub-Signature']}"` — reading the raw incoming header directly from `request.headers`, not any return value from the verification method. Inside `GitHubApp#verify_webhook_signature` [2](#0-1) , the local variable `signature` is reassigned via `algorithm, signature = signature.split("=", 2)`, but this reassignment is scoped to that method only and never mutates or is read back by the controller. The actual `webhook_secret` (`@config[:webhook_secret]`) is a private `attr_reader` [3](#0-2)  and is never interpolated into any log line in this file. Therefore both sides of the equality are evaluated: the logged string is always exactly the client-controlled `X-Hub-Signature` header value, and the secret/HMAC digest never appears in any `Rails.logger` call in this path. The equality holds (logged value == attacker input), and the claimed leak (logged value == server secret) is false.

### Impact Explanation
None. No secret, HMAC digest, or derived credential is exposed to logs or responses; the attacker only sees their own submitted header reflected back into server-side logs, which they already know since they sent it. This does not enable authentication bypass, RCE, or cross-tenant access, and does not meet any Critical/High impact category in scope.

### Likelihood Explanation
Not applicable — there is no exploitable divergence. Any unprivileged internet user can trigger this log line by POSTing to `/webhooks` with an arbitrary `X-Hub-Signature` header, but doing so only causes their own guess to be logged, not the real secret.

### Recommendation
No fix required. Optionally, for defense-in-depth/log hygiene (out of scope per rules on best-practice notes), the signature header could be omitted or truncated from logs, but this is not a security requirement since it carries no real secret material.

### Proof of Concept
```ruby
test "verify_signature never logs the configured webhook_secret" do
  secret = "s3cr3t"
  Shipit.stubs(:github).returns(stub(verify_webhook_signature: false))
  # attacker sends a bogus signature they made up
  fake_signature = "sha1=deadbeef"
  logged = nil
  Rails.logger.stub(:info, ->(msg) { logged = msg }) do
    post shipit.github_webhooks_path,
      params: { repository: { owner: { login: "acme" } } }.to_json,
      headers: { "X-Github-Event" => "push", "X-Hub-Signature" => fake_signature,
                 "Content-Type" => "application/json" }
  end
  assert_includes logged, "signature=#{fake_signature}"
  refute_includes logged, secret
end
```
This confirms the logged value equals the attacker-supplied header (`fake_signature`) and never equals the configured `webhook_secret`, validating the non-finding.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit/github_app.rb (L164-166)
```ruby
    private

    attr_reader :webhook_secret, :oauth_id, :oauth_secret
```
