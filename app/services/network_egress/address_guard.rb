# frozen_string_literal: true

require "ipaddr"
require "uri"
require "socket"
require "timeout"

module NetworkEgress
  # Resolves a URL to its actual destination addresses and decides whether an
  # agent tool may reach them.
  #
  # This exists because the previous check (Tools::HttpRequestExecutor#private_ip?)
  # only tried to parse the *hostname itself* as an IP literal:
  #
  #   ip = IPAddr.new(host) rescue nil
  #   return false unless ip          # any hostname => "not private" => allowed
  #
  # So `http://docker-proxy:2375` was permitted, as was any external hostname
  # whose DNS record points at a private address. Since the Rails and Sidekiq
  # containers can reach the unauthenticated Docker API on the internal
  # network, that was a path from one agent tool call to root on the host.
  #
  # Two tiers, deliberately different in strength:
  #
  #   1. HARD DENY (`infrastructure_denied?`) — the Docker Engine API. Not
  #      overridable by any per-agent policy, because allowlisting your way to
  #      the Docker socket is never a legitimate configuration: it is
  #      equivalent to handing an agent host root.
  #
  #   2. DEFAULT DENY (`private_destination?`) — loopback, private, link-local
  #      and friends. Overridable through an explicit agent allowlist entry, so
  #      reaching a genuine internal API stays possible but has to be a
  #      decision someone made on purpose.
  #
  # Resolution failure is a denial, not an allowance. A name we cannot resolve
  # is a name we cannot vouch for.
  class AddressGuard
    Result = Struct.new(:allowed?, :reason, :hard, keyword_init: true)

    RESOLVE_TIMEOUT = 2 # seconds

    # Docker Engine API over TCP. Reaching this is host compromise.
    DOCKER_API_PORTS = [ 2375, 2376 ].freeze

    # Ranges an agent tool has no business reaching by default.
    BLOCKED_V4 = [
      "0.0.0.0/8",        # "this host"
      "10.0.0.0/8",       # RFC1918
      "127.0.0.0/8",      # loopback
      "169.254.0.0/16",   # link-local (incl. cloud metadata 169.254.169.254)
      "172.16.0.0/12",    # RFC1918 — Docker's default bridge pools live here
      "192.168.0.0/16",   # RFC1918
      "100.64.0.0/10",    # CGNAT
      "192.0.0.0/24",     # IETF protocol assignments
      "224.0.0.0/4",      # multicast
      "240.0.0.0/4"       # reserved
    ].freeze

    BLOCKED_V6 = [
      "::1/128",          # loopback
      "::/128",           # unspecified
      "fc00::/7",         # unique local
      "fe80::/10",        # link-local
      "ff00::/8"          # multicast
    ].freeze

    class << self
      # @param url [String]
      # @return [Result] `hard: true` means no policy may override it.
      def check(url)
        uri = parse(url)
        return deny("invalid or unsupported URL", hard: true) unless uri

        if (reason = infrastructure_reason(uri))
          return deny(reason, hard: true)
        end

        addresses = resolve(uri.hostname)
        if addresses.empty?
          return deny("could not resolve host '#{uri.hostname}'", hard: false)
        end

        blocked = addresses.find { |ip| blocked_address?(ip) }
        if blocked
          return deny("host '#{uri.hostname}' resolves to non-public address #{blocked}", hard: false)
        end

        allow("destination is public")
      end

      # True when the URL targets the Docker Engine API. Never overridable.
      def infrastructure_denied?(url)
        uri = parse(url)
        return false unless uri

        !infrastructure_reason(uri).nil?
      end

      # True when any resolved address falls outside public address space.
      def private_destination?(url)
        uri = parse(url)
        return true unless uri

        addresses = resolve(uri.hostname)
        return true if addresses.empty? # unresolvable => treat as unsafe

        addresses.any? { |ip| blocked_address?(ip) }
      end

      private

      def infrastructure_reason(uri)
        return "Docker Engine API port #{uri.port} is never reachable by agent tools" if DOCKER_API_PORTS.include?(uri.port)

        nil
      end

      def parse(url)
        uri = URI.parse(url.to_s)
        return nil unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
        return nil if uri.hostname.blank?

        uri
      rescue URI::InvalidURIError, ArgumentError
        nil
      end

      # Every address the host resolves to — not just the first. A name with
      # one public and one private record must not pass on the public one.
      #
      # @return [Array<IPAddr>] empty when resolution fails
      def resolve(host)
        literal = ip_literal(host)
        return [ literal ] if literal

        Timeout.timeout(RESOLVE_TIMEOUT) do
          Addrinfo.getaddrinfo(host, nil, nil, :STREAM)
                  .map { |ai| ip_literal(ai.ip_address) }
                  .compact
                  .uniq
        end
      rescue Timeout::Error, SocketError, StandardError
        []
      end

      def ip_literal(value)
        ip = IPAddr.new(value.to_s)
        ip.ipv4_mapped? ? ip.native : ip
      rescue IPAddr::InvalidAddressError, ArgumentError
        nil
      end

      def blocked_address?(ip)
        ranges = ip.ipv4? ? blocked_v4 : blocked_v6
        ranges.any? { |range| range.include?(ip) }
      end

      def blocked_v4
        @blocked_v4 ||= BLOCKED_V4.map { |c| IPAddr.new(c) }
      end

      def blocked_v6
        @blocked_v6 ||= BLOCKED_V6.map { |c| IPAddr.new(c) }
      end

      def allow(reason)
        Result.new(allowed?: true, reason:, hard: false)
      end

      def deny(reason, hard:)
        Result.new(allowed?: false, reason:, hard:)
      end
    end
  end
end
