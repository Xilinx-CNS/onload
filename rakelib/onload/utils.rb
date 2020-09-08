# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2019 Xilinx, Inc.

require 'English'
require_relative './log'

module Onload
  module Utils
    def self.raise_red(msg)
      raise Onload::Log.colourise('bold', Onload::Log.colourise('red', msg))
    end

    def self.check_success(*cmd, logfile: nil, env: {})
      cmd_str = cmd.join(' ')
      puts(cmd_str)
      rc = nil
      output_file = nil
      output = []
      unless logfile.nil?
        FileUtils.mkdir_p logfile.dirname
        logfile.unlink if logfile.exist?
        output_file = File.open(logfile, 'a')
      end
      IO.popen(env, cmd_str) do |command_output|
        command_output.each do |line|
          output << line
          puts line
          $stdout.flush
          output_file.write(line) unless output_file.nil?
        end
        command_output.close
        rc = $CHILD_STATUS
      end
      puts "Command returned: #{rc.to_i}"
      raise_red "#{cmd_str}: failed with error #{rc.exitstatus}" unless rc.to_i.zero?
      return output.join
    end

    def self.sudo(*cmd)
      check_success 'sudo', *cmd
    end

    def self.make(dir, *cmd, env: {})
      check_success 'make', '-C', dir, *cmd, env: env
    end

    def self.add_to_path(dir, index = 0)
      dirs = ENV['PATH'].split(':')
      dirs.insert(index, dir)
      ENV['PATH'] = dirs.join(':')
    end
  end
end
