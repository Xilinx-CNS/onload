# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2019 Xilinx, Inc.

namespace :graph do
  graph_dot = '/tmp/graph.dot'
  graph_png = '/tmp/graph.png'

  task :dot do
    File.open(graph_dot, 'w') do |f|
      f.puts 'digraph g {'
      Rake::Task.tasks.each do |task|
        next if task.name.split(':')[0] == 'graph'

        f.print "\"#{task.name}\" ["
        node = {}
        comment = ENV.key?('GRAPH_DESC') && task.comment
        node[:label] = "#{task.name}\n#{task.comment}" if comment
        node[:style] = 'filled'
        if task.comment
          node[:color] = 'forestgreen'
          node[:fontcolor] = 'black'
        else
          node[:color] = 'grey90'
          node[:fontcolor] = 'grey30'
          node[:fontsize] = 10
        end
        node.each do |k,v|
          f.print " #{k}=\"#{v}\""
        end
        f.puts '];'
        task.prerequisite_tasks.each do |prereq|
          f.puts "\"#{prereq.name}\" -> \"#{task.name}\";"
        end
      end
      f.puts '}'
    end
  end

  task png: [:dot] do
    sh "dot -Tpng #{graph_dot} > #{graph_png}"
  end

  task show: [:png] do
    sh "display #{graph_png} &"
  end
end

desc 'Show a graph of tasks with their dependencies.

Set GRAPH_DESC=1 to include task descriptions'

task 'graph' => ['graph:show'] do
end
