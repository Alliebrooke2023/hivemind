# frozen_string_literal: true

require "ipaddr"
require "uri"

module NetworkEgress
  class PolicyCheck
    Result = Struct.new(:allowed?, :reason, keyword_init: true)

    def self.call(agent:, url:)
      new(agent:, url:).call
    end

    def initialize(agent:, url:)
      @agent = agent
      @url = url
    end

    def call
      policy = @agent.effective_egress_policy
      mode = policy[:mode]

      uri = parse_uri
      return deny("invalid URL: #{@url}") unless uri

      host = uri.host
      port = uri.port
      rules = Array(policy[:rules])

      # The address guard runs before, and independently of, the per-agent
      # policy. Previously a blank policy meant "allow all", which let an
      # agent with no configuration reach internal services — including the
      # Docker Engine API, i.e. root on the host.
      guard_result = apply_address_guard(host, port, mode, rules, policy)
      return guard_result if guard_result

      # No policy or disabled → allow any destination the guard accepted
      return allow("no egress policy") if mode.blank? || mode == "disabled"

      case mode
      when "allowlist"
        check_allowlist(host, port, rules, policy)
      when "blocklist"
        check_blocklist(host, port, rules, policy)
      else
        allow("unknown mode")
      end
    end

    private

    # @return [Result, nil] a denial, or nil when the destination is acceptable
    def apply_address_guard(host, port, mode, rules, policy)
      guard = AddressGuard.check(@url)
      return nil if guard.allowed?

      # Hard denials (the Docker Engine API) are never overridable — there is
      # no legitimate reason to allowlist an agent into the container runtime.
      # Soft denials (private/loopback destinations) can be overridden by an
      # explicit allowlist entry, so reaching a real internal API stays
      # possible but has to be chosen deliberately.
      if !guard.hard && mode == "allowlist" && rules.any? { |rule| matches_rule?(host, port, rule) }
        return nil
      end

      log_guard_denial(host, port, guard)
      deny("egress guard: #{guard.reason}")
    end

    # Guard denials are security events, so they are recorded regardless of
    # the policy's log_blocked flag.
    def log_guard_denial(host, port, guard)
      AuditLog.record(
        actor_type: "agent",
        actor_id: @agent.id,
        action: "network_egress.guard_blocked",
        metadata: {
          url: @url,
          host:,
          port:,
          reason: guard.reason,
          hard: guard.hard
        }
      )
    rescue StandardError => e
      Rails.logger.error("[NetworkEgress] failed to audit guard denial: #{e.message}")
    end

    def check_allowlist(host, port, rules, policy)
      if rules.any? { |rule| matches_rule?(host, port, rule) }
        allow("host matches allowlist")
      else
        result = deny("host '#{host}' not in allowlist")
        log_blocked(host, port, "not in allowlist", policy)
        result
      end
    end

    def check_blocklist(host, port, rules, policy)
      matching_rule = rules.find { |rule| matches_rule?(host, port, rule) }
      if matching_rule
        result = deny("host '#{host}' matches blocklist pattern '#{matching_rule['pattern'] || matching_rule[:pattern]}'")
        log_blocked(host, port, "matches blocklist", policy)
        result
      else
        allow("host not in blocklist")
      end
    end

    def matches_rule?(host, port, rule)
      rule = rule.with_indifferent_access
      pattern = rule[:pattern].to_s.strip
      rule_port = rule[:port]

      return false if rule_port.present? && rule_port.to_i != port

      matches_pattern?(host, pattern)
    end

    def matches_pattern?(host, pattern)
      return false if host.blank? || pattern.blank?

      # CIDR notation check
      if pattern.include?("/")
        return cidr_match?(host, pattern)
      end

      # Glob pattern (*.example.com)
      if pattern.start_with?("*.")
        suffix = pattern[1..] # ".example.com"
        return host == pattern[2..] || host.end_with?(suffix)
      end

      # Exact match
      host.downcase == pattern.downcase
    end

    def cidr_match?(host, cidr)
      ip = IPAddr.new(host)
      network = IPAddr.new(cidr)
      network.include?(ip)
    rescue IPAddr::InvalidAddressError
      false
    end

    def parse_uri
      uri = URI.parse(@url)
      return nil unless uri.host.present?
      uri
    rescue URI::InvalidURIError
      nil
    end

    def allow(reason)
      Result.new(allowed?: true, reason:)
    end

    def deny(reason)
      Result.new(allowed?: false, reason:)
    end

    def log_blocked(host, port, reason, policy)
      return unless policy[:log_blocked]

      AuditLog.record(
        actor_type: "agent",
        actor_id: @agent.id,
        action: "network_egress.blocked",
        metadata: {
          url: @url,
          host:,
          port:,
          reason:,
          policy_mode: policy[:mode]
        }
      )
    end
  end
end
