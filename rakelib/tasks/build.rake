# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc.

require 'pathname'

toppath = nil
$user_build_dir = nil
$kernel_build_dir = nil
$efct_build_dir = nil

namespace :build do
  task :scripts_in_path do
    Onload::Utils.add_to_path(File.join(pwd, 'scripts'))
  end

  task toppath: [:scripts_in_path] do
    toppath = `mmaketool --toppath`.chomp
  end

  task user_build_tree: [:toppath] do
    ENV['ZF_DEVEL'] = '1'
    sh 'mmakebuildtree --gnu'
    userbuild = `mmaketool --userbuild`.chomp
    $user_build_dir = File.join(toppath, 'build', userbuild)
  end

  task kernel_build_tree: [:toppath] do
    Onload::Utils.add_to_path(File.join(pwd, 'scripts'))
    sh 'mmakebuildtree --driver'
    kernelbuild = `mmaketool --driverbuild`.chomp
    $kernel_build_dir = File.join(toppath, 'build', kernelbuild)
  end

  task efct_build_tree: [:toppath] do
    Onload::Utils.add_to_path(File.join(pwd, 'scripts'))
    sh 'mmakebuildtree --driver'
    kernelbuild = `mmaketool --driverbuild`.chomp
    $efct_build_dir = File.join(toppath, 'build', kernelbuild)
  end

  task :choose_compiler do
    # Choose compiler
    if ENV.key?('ZF_CC')
      zf_cc = ENV['ZF_CC']
    else
      zf_cc = File.readlink('/opt/zf/cc') if File.exist?('/opt/zf/cc')
      zf_cc = '/opt/rh/devtoolset-7/root/usr/bin/cc' unless zf_cc && File.executable?(zf_cc)
    end
    zf_cc = 'cc' unless zf_cc && File.executable?(zf_cc)
    ENV['CC'] = ENV['ZF_CC'] = zf_cc
  end

  # Used by the pipeline to know which gcov to tell gcovr to use
  task which_gcov: [:choose_compiler] do
    cc_bindir = File.dirname(ENV['ZF_CC'])
    gcov = File.join(cc_bindir, 'gcov')
    gcov = '/usr/bin/gcov' unless File.executable?(gcov)
    puts gcov
  end

  task user_compiler_setup: [:choose_compiler] do
    ENV['GCOV'] = '1' if ENV.key?('COVERAGE') && ENV['COVERAGE'] == '1'

    puts "Using compiler #{ENV['ZF_CC']}"
  end

  task :kernel_compiler_setup do
    [ 'CC', 'ZF_CC', 'ZF_DEVEL', 'GCOV' ].each do |var|
      ENV.delete(var)
    end
  end

  task header_deps: [:user_build_tree, :user_compiler_setup] do
    Dir.chdir($user_build_dir) do
      Onload::Utils.make('include')
    end
  end

  desc 'Kernel driver build'
  task kernel_driver: [:kernel_build_tree, :kernel_compiler_setup] do
    Onload::Utils.make($kernel_build_dir)
  end

  desc 'Userspace build (64 bit)'
  task userspace: [:user_build_tree, :user_compiler_setup] do
    Onload::Utils.make($user_build_dir)
  end

  desc 'efct_build'
  task efct_driver: [:efct_build_tree, :kernel_compiler_setup] do
    if Dir.exist?(File.join(toppath, 'aux-bus'))
      ENV['AUX_BUS_PATH'] = File.join(toppath, 'aux-bus')
      puts "Using AUX PATH #{ENV['AUX_BUS_PATH']}"
      puts "Attempting to compile aux bus"
      Onload::Utils.make(File.join(toppath, 'aux-bus'))
    end
    if Dir.exist?(File.join(toppath, 'x3-net'))
      ENV['X3_NET_PATH'] = File.join(toppath, 'x3-net')
      puts "Using X3 PATH #{ENV['X3_NET_PATH']}"
    end
    Onload::Utils.make($efct_build_dir)
  end


  desc 'Build everything'
  task all: [:kernel_driver, :userspace]

  # For each (recognised) subdirectory of lib, create a task to build it, with
  # the task named after the subdirectory.  All the tasks are defined with a
  # 'lib' namespace, hence tasks such as 'build:lib:citools'
  TEST_REQUIRED_LIBRARIES = [
    'ciapp',
    'ciul',
    'cplane',
    'citools',
    'zf',
    'ip',
  ]
  namespace :lib do
    (Dir.glob(File.join(pwd, 'src/lib/*')) +
     Dir.glob(File.join(pwd, 'src/lib/transport/*')))
      .select { |entry| File.exist?(File.join(entry, 'mmake.mk')) }
      .reject { |entry| ['tests'].include?(File.basename(entry)) }
      .select { |entry| TEST_REQUIRED_LIBRARIES.include?(File.basename(entry)) }
      .each do |path|

      dirname = File.basename(path)
      basepath = Pathname.new(File.join(pwd, 'src'))
      subdir = Pathname.new(path).relative_path_from(basepath).to_s

      task dirname.to_sym => [:header_deps] do
        Dir.chdir($user_build_dir) do
          Onload::Utils.make(subdir)
        end
      end
    end

    # Define inter-library dependencies
    task zf: [:ciul, :cplane, :citools]
  end
end
