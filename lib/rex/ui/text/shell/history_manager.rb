# -*- coding: binary -*-

module Rex
module Ui
module Text
module Shell

class HistoryManager

  @@contexts = []

  def self.inspect
    "#<HistoryManager stack size: #{@@contexts.length}>"
  end

  def self.context_stack
    @@contexts
  end

  def self.push_context(history_file: nil, name: nil)
    dlog("HistoryManager.push_context name: #{name.inspect}")
    @@contexts.push({:history_file => history_file, :name => name})

    if history_file
      self.load_history_file(history_file)
    else
      clear_readline
    end

    @@original_histsize = Readline::HISTORY.size
  end

  def self.pop_context
    if @@contexts.empty?
      elog("HistoryManager.pop_context called even when the stack was already empty!")
      return
    end

    history_file, name = @@contexts.pop.values
    if history_file
      cmds = []
      history_diff = Readline::HISTORY.size - @@original_histsize
      history_diff.times do
        cmds.push(Readline::HISTORY.pop)
      end
      File.open(history_file, 'a+') do |f|
        f.puts(cmds.reverse)
      end
    end

    unless @@contexts.empty?
      history_file = @@contexts.last[:history_file]
      self.load_history_file(history_file) unless history_file.nil?
    end

    dlog("HistoryManager.pop_context name: #{name.inspect}")
  end

  def self.with_context(**kwargs, &block)
    self.push_context(**kwargs)

    begin
      block.call
    ensure
      self.pop_context
    end
  end

  class << self
    private

    def load_history_file(history_file)
      clear_readline
      if File.exist?(history_file)
        File.readlines(history_file).each do |e|
          Readline::HISTORY << e.chomp
        end
      end
    end

    def clear_readline
      Readline::HISTORY.length.times { Readline::HISTORY.pop }
    end

  end
end

end
end
end
end
