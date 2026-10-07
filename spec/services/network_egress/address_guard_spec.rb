# frozen_string_literal: true

require "rails_helper"

RSpec.describe NetworkEgress::AddressGuard do
  # DNS is stubbed throughout so these specs are deterministic and run offline.
  def stub_resolution(*addresses)
    allow(Addrinfo).to receive(:getaddrinfo)
      .and_return(addresses.map { |a| instance_double(Addrinfo, ip_address: a) })
  end

  describe ".check" do
    context "hard denials (not overridable by any policy)" do
      it "denies the Docker Engine API port on any host" do
        result = described_class.check("http://docker-proxy:2375/containers/json")
        expect(result.allowed?).to be false
        expect(result.hard).to be true
        expect(result.reason).to include("Docker Engine API")
      end

      it "denies the TLS Docker API port too" do
        expect(described_class.check("https://anything:2376/info").allowed?).to be false
      end

      it "denies non-HTTP schemes" do
        result = described_class.check("file:///etc/passwd")
        expect(result.allowed?).to be false
        expect(result.hard).to be true
      end

      it "denies unparseable URLs" do
        expect(described_class.check("not a url").allowed?).to be false
      end
    end

    context "hostname resolution" do
      it "denies a hostname resolving to a Docker bridge address" do
        stub_resolution("172.18.0.4")
        result = described_class.check("http://docker-proxy/info")
        expect(result.allowed?).to be false
        expect(result.hard).to be false
        expect(result.reason).to include("172.18.0.4")
      end

      it "denies when any resolved address is non-public, not just the first" do
        stub_resolution("93.184.216.34", "10.0.0.5")
        expect(described_class.check("http://split-horizon.example/").allowed?).to be false
      end

      it "allows a hostname resolving only to public addresses" do
        stub_resolution("93.184.216.34")
        expect(described_class.check("https://example.com/page").allowed?).to be true
      end

      it "fails closed when resolution raises" do
        allow(Addrinfo).to receive(:getaddrinfo).and_raise(SocketError)
        result = described_class.check("http://nope.invalid/")
        expect(result.allowed?).to be false
        expect(result.reason).to include("could not resolve")
      end

      it "fails closed when resolution returns nothing" do
        allow(Addrinfo).to receive(:getaddrinfo).and_return([])
        expect(described_class.check("http://empty.invalid/").allowed?).to be false
      end

      it "does not resolve IP literals" do
        expect(Addrinfo).not_to receive(:getaddrinfo)
        expect(described_class.check("https://93.184.216.34/").allowed?).to be true
      end
    end

    context "IPv4 ranges" do
      {
        "loopback"          => "127.0.0.1",
        "RFC1918 10/8"      => "10.1.2.3",
        "RFC1918 172.16/12" => "172.20.1.1",
        "RFC1918 192.168"   => "192.168.1.1",
        "link-local"        => "169.254.169.254",
        "CGNAT"             => "100.64.0.1",
        "this-host"         => "0.0.0.0",
        "multicast"         => "224.0.0.1"
      }.each do |label, ip|
        it "denies #{label} (#{ip})" do
          expect(described_class.check("http://#{ip}/").allowed?).to be false
        end
      end

      it "allows an ordinary public address" do
        expect(described_class.check("https://93.184.216.34/").allowed?).to be true
      end
    end

    context "IPv6 ranges" do
      it "denies IPv6 loopback" do
        expect(described_class.check("http://[::1]/").allowed?).to be false
      end

      it "denies unique-local addresses" do
        expect(described_class.check("http://[fd00::1]/").allowed?).to be false
      end

      it "denies link-local addresses" do
        expect(described_class.check("http://[fe80::1]/").allowed?).to be false
      end

      it "denies IPv4-mapped IPv6 pointing at loopback" do
        expect(described_class.check("http://[::ffff:127.0.0.1]/").allowed?).to be false
      end

      it "denies IPv4-mapped IPv6 pointing at a private address" do
        expect(described_class.check("http://[::ffff:10.0.0.1]/").allowed?).to be false
      end
    end
  end

  describe ".infrastructure_denied?" do
    it "is true for the Docker API" do
      expect(described_class.infrastructure_denied?("http://docker-proxy:2375/")).to be true
    end

    it "is false for an ordinary URL" do
      expect(described_class.infrastructure_denied?("https://example.com/")).to be false
    end
  end

  describe ".private_destination?" do
    it "is true for loopback" do
      expect(described_class.private_destination?("http://127.0.0.1/")).to be true
    end

    it "is true for an unresolvable host" do
      allow(Addrinfo).to receive(:getaddrinfo).and_raise(SocketError)
      expect(described_class.private_destination?("http://nope.invalid/")).to be true
    end

    it "is false for a public address" do
      stub_resolution("93.184.216.34")
      expect(described_class.private_destination?("https://example.com/")).to be false
    end
  end
end
