# frozen_string_literal: true

require "open3"
require "timeout"
require "fileutils"
require "shellwords"
require "securerandom"

module Tools
  # Executes a user- or agent-authored script template.
  #
  # SECURITY: this previously ran `Open3.capture3("bash", "-c", command)`
  # directly inside the Rails/Sidekiq container. That container holds
  # DOCKER_HOST and shares the internal network with the Docker Engine API,
  # so a custom script was a path out of the agent sandbox to host root —
  # unlike Tools::ShellExecutor, which has always executed inside the
  # dedicated `workspace` container.
  #
  # Scripts now run in that same workspace container. When it is unreachable
  # we refuse instead of falling back to local execution: a fallback running
  # in the application container would reintroduce the exact escape this
  # closes.
  class CustomScriptExecutor < BaseExecutor
    EXEC_TIMEOUT = 60
    MAX_OUTPUT = 50_000
    WORKSPACE_ROOT = "/workspace"
    EXEC_DIR = "/workspace/.hivemind/exec"
    WORKSPACE_CONTAINER = "#{ENV.fetch('COMPOSE_PROJECT_NAME', 'hivemind')}-workspace-1"

    SANDBOX_UNAVAILABLE = "Custom script tools run in the workspace sandbox container, " \
                          "which is not reachable. Refusing to execute in the application " \
                          "container."

    def call
      template = config["script_template"].to_s.strip
      return ServiceResponse.failure(error: "No script template configured for this tool") if template.empty?

      # Interpolate {{param}} placeholders with shell-escaped input values
      command = interpolate_template(template)

      output, exit_code = execute_command(command)

      if exit_code == 0
        ServiceResponse.success(data: { output: output.to_s.truncate(MAX_OUTPUT), exit_code: exit_code })
      else
        ServiceResponse.failure(
          error: "Script exited with code #{exit_code}",
          data: { output: output.to_s.truncate(MAX_OUTPUT), exit_code: exit_code }
        )
      end
    rescue Timeout::Error
      ServiceResponse.failure(error: "Script timed out after #{EXEC_TIMEOUT}s")
    rescue StandardError => e
      ServiceResponse.failure(error: "Script execution failed: #{e.message}")
    end

    private

    def interpolate_template(template)
      result = template.dup

      # Replace {{param_name}} with shell-escaped input values
      result.gsub!(/\{\{(\w+)\}\}/) do
        param_name = Regexp.last_match(1)
        value = input[param_name] || input[param_name.to_sym]
        if value.nil?
          "" # Missing params become empty string
        else
          Shellwords.escape(value.to_s)
        end
      end

      result
    end

    # Runs the script inside the workspace container, mirroring
    # Tools::ShellExecutor. Fails closed when Docker is unavailable.
    def execute_command(command)
      return [ SANDBOX_UNAVAILABLE, 1 ] unless docker_available?

      script_path = File.join(EXEC_DIR, "custom-#{SecureRandom.hex(8)}.sh")

      begin
        ensure_exec_dir
        write_script(script_path, command)
        run_script(script_path)
      ensure
        remove_script(script_path)
      end
    end

    def write_script(script_path, command)
      script_content = <<~BASH
        #!/bin/bash
        cd #{WORKSPACE_ROOT}
        #{command}
      BASH

      IO.popen(
        [ "docker", "exec", "-i", WORKSPACE_CONTAINER,
          "bash", "-c", "cat > #{script_path} && chmod 700 #{script_path}" ],
        "w"
      ) { |io| io.write(script_content) }
    end

    def run_script(script_path)
      output = ""
      exit_code = 1

      Timeout.timeout(EXEC_TIMEOUT) do
        stdout, stderr, status = Open3.capture3(
          "docker", "exec", WORKSPACE_CONTAINER,
          "bash", "-c", "#{script_path} 2>&1; echo \"__HIVEMIND_EXIT__$?\""
        )

        lines = stdout.to_s.lines
        if lines.last&.start_with?("__HIVEMIND_EXIT__")
          exit_code = lines.last.sub("__HIVEMIND_EXIT__", "").strip.to_i
          output = lines[0..-2].join
        else
          exit_code = status&.exitstatus || 1
          output = stdout.to_s
        end

        output += "\nSTDERR: #{stderr}" if stderr.present? && !status&.success?
      end

      [ output, exit_code ]
    end

    def ensure_exec_dir
      Open3.capture3(
        "docker", "exec", WORKSPACE_CONTAINER,
        "bash", "-c", "mkdir -p #{EXEC_DIR}"
      )
    end

    def remove_script(script_path)
      Open3.capture3(
        "docker", "exec", WORKSPACE_CONTAINER,
        "bash", "-c", "rm -f #{script_path}"
      )
    rescue StandardError
      nil
    end

    def docker_available?
      return @docker_available if defined?(@docker_available)

      @docker_available = begin
        _, _, status = Open3.capture3("docker", "info")
        status.success?
      rescue StandardError
        false
      end
    end
  end
end
