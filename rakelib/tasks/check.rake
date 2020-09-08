# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc.

require 'nokogiri'

test_results_root = nil

def rewrite_junit_xml(test_results_dir, new_tag)
  Dir.glob(File.join(test_results_dir, '*'))
     .select { |filename| File.file?(filename) }
     .each do |filename|

    doc = Nokogiri::XML(File.open(filename))
    doc.xpath('//testsuite').each do |node|
      testsuite_name = node.attribute('name')
      testsuite_name.value = new_tag + '.' + testsuite_name.value
    end
    f = File.open(filename, 'w')
    f.puts(doc.to_s)
  end
end

# All Unit tests should live under the 'check' namespace.  Each thread of test
# (oof, orm, cplane etc.) should define its own namespace within which it should
# have two tasks.  The first 'build' should compile the tests, the second
# 'execute' should run the tests.
namespace :check do
  task lib_kernel_compat: ['build:header_deps'] do
    Dir.chdir($user_build_dir) do
      sh 'make -C lib/kcompat'
    end
  end


  # cplane system tests
  namespace :cplane_sys do |nm|
    namespace_leaf_name = ENV['TEST_THREAD_NAME'] || nm.scope.path.split(':')[-1]

    # build the cplane system tests
    task build: ['build:lib:citools', 'build:lib:ciapp'] do
      Dir.chdir($user_build_dir) do
        Onload::Utils.make('tests/onload/cplane_sysunit')
      end
    end

    # run the cplane system tests
    task execute: [:precheck, :build] do
      test_results_dir = File.join(test_results_root, namespace_leaf_name)
      Dir.chdir($user_build_dir) do
        begin
          Onload::Utils.make('tests/onload/cplane_sysunit', 'test', "UNIT_TEST_OUTPUT=#{test_results_dir}")
        ensure
          rewrite_junit_xml(test_results_dir, namespace_leaf_name)
        end
      end
    end
  end
  desc 'Run cplane_sys tests'
  task cplane_sys: [:'cplane_sys:execute']

  namespace :unit do |nm|
    # cplane unit tests
    namespace :cplane do |nm|
      namespace_leaf_name = ENV['TEST_THREAD_NAME'] || nm.scope.path.split(':')[-1]

      # build the cplane unit tests
      task build: ['build:lib:citools', 'build:lib:ciapp', 'build:lib:ciul', 'build:lib:cplane', 'build:lib:ip'] do
        Dir.chdir($user_build_dir) do
          Onload::Utils.make('tests/onload/cplane_unit')
        end
      end

      # run the cplane unit tests
      task execute: [:precheck, :build] do
        test_results_dir = File.join(test_results_root, namespace_leaf_name)
        Dir.chdir($user_build_dir) do
          begin
            Onload::Utils.make('tests/onload/cplane_unit', 'test', "UNIT_TEST_OUTPUT=#{test_results_dir}")
          ensure
            rewrite_junit_xml(test_results_dir, namespace_leaf_name)
          end
        end
      end
    end
    desc 'Run cplane unit tests'
    task cplane: [:'cplane:execute']

    # oof unit tests
    namespace :oof do |nm|
      namespace_leaf_name = ENV['TEST_THREAD_NAME'] || nm.scope.path.split(':')[-1]

      task build: [:lib_kernel_compat, 'build:lib:citools'] do
        Dir.chdir($user_build_dir) do
          Onload::Utils.make('tests/onload/oof')
        end
      end

      task execute: [:precheck, :build] do
        test_results_dir = File.join(test_results_root, namespace_leaf_name)
        Dir.chdir($user_build_dir) do
          begin
            Onload::Utils.make('tests/onload/oof', 'tests', "UNIT_TEST_OUTPUT=#{test_results_dir}")
          ensure
            rewrite_junit_xml(test_results_dir, namespace_leaf_name)
          end
        end
      end
    end
    desc 'Run oof unit tests'
    task oof: [:'oof:execute']

    # orm unit tests
    namespace :orm do |nm|
      namespace_leaf_name = ENV['TEST_THREAD_NAME'] || nm.scope.path.split(':')[-1]

      task build: ['build:header_deps'] do
        Dir.chdir($user_build_dir) do
          Onload::Utils.make('tests/onload/onload_remote_monitor/internal_tests')
        end
      end

      task execute: [:precheck, :build] do
        test_results_dir = File.join(test_results_root, namespace_leaf_name)
        Dir.chdir($user_build_dir) do
          begin
            Onload::Utils.make('tests/onload/onload_remote_monitor/internal_tests', 'test', "UNIT_TEST_OUTPUT=#{test_results_dir}")
          ensure
            rewrite_junit_xml(test_results_dir, namespace_leaf_name)
          end
        end
      end
    end
    desc 'Run orm unit tests'
    task orm: [:'orm:execute']

    # zf unit tests
    namespace :zf do |nm|
      namespace_leaf_name = ENV['TEST_THREAD_NAME'] || nm.scope.path.split(':')[-1]

      task build: ['build:lib:zf'] do
        Dir.chdir($user_build_dir) do
          Onload::Utils.make('tests/zf_apps')
          Onload::Utils.make('tests/zf_unit')
          Onload::Utils.make('tests/packetdrill')
        end
      end

      task execute: [:precheck, :build] do
        test_results_dir = File.join(test_results_root, namespace_leaf_name)
        caught = []

        Dir.chdir($user_build_dir) do
          begin
            Onload::Utils.make 'tests/zf_unit', 'test', "UNIT_TEST_OUTPUT=#{test_results_dir}"
          rescue RuntimeError => exception
            puts "Caught: #{exception}"
            caught << exception
          end

          begin
            Onload::Utils.make('tests/zf_unit', 'testpacketdrill', "UNIT_TEST_OUTPUT=#{test_results_dir}")
          rescue RuntimeError => exception
            puts "Caught: #{exception}"
            caught << exception
          end
        end

        rewrite_junit_xml(test_results_dir, namespace_leaf_name)
        raise caught[0] unless caught.empty?
      end
    end
    desc 'Run zf unit tests'
    task zf: [:'zf:execute']
  end
end

task :precheck do
  if ENV.key?('TEST_RESULTS')
    test_results_root = ENV['TEST_RESULTS']

  else
    raise 'Test results path not given. Specify it as "rake check TEST_RESULTS=<your-choice-of-path>"'
  end

  # Clear down test directory
  FileUtils.rm_rf(test_results_root) if test_results_root
end

desc 'Run all unit tests'
task check: [
       :'check:unit:cplane',
       :'check:cplane_sys',
       :'check:unit:oof',
       :'check:unit:orm',
       :'check:unit:zf',
     ]
