# SPDX-License-Identifier: Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

$LOAD_PATH.unshift('.')

require 'etc'
require 'fileutils'
require 'pathname'

require 'rake/clean'

Rake::TaskManager.record_task_metadata = true

# Intermediate temporary working files
CLEAN.include('*.tmp', 'build/import/**')

# Final targets
CLOBBER.include('build')

Pathname.glob(File.join('rakelib', 'tasks', '**', '*.rake')).each do |f|
  desc ''
  import f
end

require 'rakelib/onload'
