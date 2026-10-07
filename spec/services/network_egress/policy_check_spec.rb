# frozen_string_literal: true

require "rails_helper"

RSpec.describe NetworkEgress::PolicyCheck do
  let(:agent) { create(:agent) }

  # The address guard resolves hostnames before the policy is consulted, so
  # stub DNS to keep these specs deterministic and runnable offline. A public
  # address is the default; contexts that care override it.
  before do
    allow(Addrinfo).to receive(:getaddrinfo)
      .and_return([ instance_double(Addrinfo, ip_address: "93.184.216.34") ])
  end

  describe ".call" do
    context "with no egress policy" do
      it "allows all requests" do
        result = described_class.call(agent: agent, url: "https://example.com")
        expect(result.allowed?).to be true
      end
    end

    context "with disabled mode" do
      before do
        agent.update!(egress_policy: { "mode" => "disabled", "rules" => [] })
      end

      it "allows all requests" do
        result = described_class.call(agent: agent, url: "https://example.com")
        expect(result.allowed?).to be true
      end
    end

    context "with allowlist mode" do
      before do
        agent.update!(egress_policy: {
          "mode" => "allowlist",
          "rules" => [
            { "pattern" => "api.github.com" },
            { "pattern" => "*.example.com" }
          ],
          "log_blocked" => true
        })
      end

      it "allows exact match" do
        result = described_class.call(agent: agent, url: "https://api.github.com/repos")
        expect(result.allowed?).to be true
      end

      it "allows glob match" do
        result = described_class.call(agent: agent, url: "https://sub.example.com/page")
        expect(result.allowed?).to be true
      end

      it "allows glob root domain match" do
        result = described_class.call(agent: agent, url: "https://example.com/page")
        expect(result.allowed?).to be true
      end

      it "blocks non-matching host" do
        result = described_class.call(agent: agent, url: "https://evil.com/steal")
        expect(result.allowed?).to be false
        expect(result.reason).to include("not in allowlist")
      end

      it "logs blocked requests to AuditLog" do
        expect {
          described_class.call(agent: agent, url: "https://evil.com/steal")
        }.to change(AuditLog, :count).by(1)

        log = AuditLog.last
        expect(log.action).to eq("network_egress.blocked")
        expect(log.actor_type).to eq("agent")
        expect(log.actor_id).to eq(agent.id.to_s)
        expect(log.metadata["host"]).to eq("evil.com")
      end
    end

    context "with blocklist mode" do
      before do
        agent.update!(egress_policy: {
          "mode" => "blocklist",
          "rules" => [
            { "pattern" => "*.evil.com" },
            { "pattern" => "malware.net" }
          ],
          "log_blocked" => true
        })
      end

      it "blocks matching glob pattern" do
        result = described_class.call(agent: agent, url: "https://sub.evil.com/page")
        expect(result.allowed?).to be false
        expect(result.reason).to include("matches blocklist")
      end

      it "blocks exact match" do
        result = described_class.call(agent: agent, url: "https://malware.net/bad")
        expect(result.allowed?).to be false
      end

      it "allows non-matching host" do
        result = described_class.call(agent: agent, url: "https://github.com/good")
        expect(result.allowed?).to be true
      end

      it "logs blocked requests" do
        expect {
          described_class.call(agent: agent, url: "https://malware.net/x")
        }.to change(AuditLog, :count).by(1)
      end
    end

    # Uses public documentation ranges (RFC 5737) rather than RFC 1918
    # addresses, so these exercise CIDR matching rather than tripping the
    # address guard, which now denies private destinations outright.
    context "with CIDR notation" do
      before do
        agent.update!(egress_policy: {
          "mode" => "blocklist",
          "rules" => [ { "pattern" => "203.0.113.0/24" } ],
          "log_blocked" => false
        })
      end

      it "blocks IP within CIDR range" do
        result = described_class.call(agent: agent, url: "http://203.0.113.5/internal")
        expect(result.allowed?).to be false
      end

      it "allows IP outside CIDR range" do
        result = described_class.call(agent: agent, url: "http://198.51.100.7/external")
        expect(result.allowed?).to be true
      end

      it "does not log when log_blocked is false" do
        expect {
          described_class.call(agent: agent, url: "http://203.0.113.5/internal")
        }.not_to change(AuditLog, :count)
      end
    end

    context "with port matching" do
      before do
        agent.update!(egress_policy: {
          "mode" => "allowlist",
          "rules" => [
            { "pattern" => "api.example.com", "port" => 443 }
          ],
          "log_blocked" => false
        })
      end

      it "allows matching host and port" do
        result = described_class.call(agent: agent, url: "https://api.example.com/data")
        expect(result.allowed?).to be true
      end

      it "blocks matching host with wrong port" do
        result = described_class.call(agent: agent, url: "http://api.example.com/data")
        expect(result.allowed?).to be false
      end
    end

    context "with invalid URL" do
      before do
        agent.update!(egress_policy: { "mode" => "allowlist", "rules" => [] })
      end

      it "denies invalid URLs" do
        result = described_class.call(agent: agent, url: "not a url")
        expect(result.allowed?).to be false
        expect(result.reason).to include("invalid URL")
      end
    end

    # Regression coverage for the SSRF hole this guard closes. Previously a
    # blank policy meant "allow all", and the only check parsed the hostname
    # as an IP literal — so `http://docker-proxy:2375` was permitted, giving
    # an agent tool call a path to the Docker Engine API, i.e. host root.
    context "address guard, with no egress policy configured" do
      it "denies the Docker Engine API by port" do
        result = described_class.call(agent: agent, url: "http://docker-proxy:2375/containers/json")
        expect(result.allowed?).to be false
        expect(result.reason).to include("Docker Engine API")
      end

      it "denies a hostname that resolves to a private address" do
        allow(Addrinfo).to receive(:getaddrinfo)
          .and_return([ instance_double(Addrinfo, ip_address: "172.18.0.4") ])

        result = described_class.call(agent: agent, url: "http://docker-proxy/info")
        expect(result.allowed?).to be false
        expect(result.reason).to include("non-public address")
      end

      it "denies the cloud metadata endpoint" do
        result = described_class.call(agent: agent, url: "http://169.254.169.254/latest/meta-data/")
        expect(result.allowed?).to be false
      end

      it "denies loopback" do
        result = described_class.call(agent: agent, url: "http://127.0.0.1:3000/")
        expect(result.allowed?).to be false
      end

      it "denies a host that cannot be resolved, rather than failing open" do
        allow(Addrinfo).to receive(:getaddrinfo).and_raise(SocketError)

        result = described_class.call(agent: agent, url: "http://nope.invalid/")
        expect(result.allowed?).to be false
        expect(result.reason).to include("could not resolve")
      end

      it "still allows public destinations" do
        result = described_class.call(agent: agent, url: "https://example.com/page")
        expect(result.allowed?).to be true
      end

      it "audits guard denials even when log_blocked is unset" do
        expect {
          described_class.call(agent: agent, url: "http://127.0.0.1/")
        }.to change(AuditLog, :count).by(1)
      end
    end

    context "address guard, with an explicit allowlist" do
      it "permits a private address that was deliberately allowlisted" do
        agent.update!(egress_policy: {
          "mode" => "allowlist",
          "rules" => [ { "pattern" => "10.1.2.3" } ],
          "log_blocked" => false
        })

        result = described_class.call(agent: agent, url: "http://10.1.2.3/internal")
        expect(result.allowed?).to be true
      end

      it "still refuses the Docker Engine API, which no policy may override" do
        agent.update!(egress_policy: {
          "mode" => "allowlist",
          "rules" => [ { "pattern" => "docker-proxy" } ],
          "log_blocked" => false
        })

        result = described_class.call(agent: agent, url: "http://docker-proxy:2375/containers/json")
        expect(result.allowed?).to be false
      end
    end
  end
end
