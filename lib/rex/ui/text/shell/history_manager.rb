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
    new_context = {:history_file => history_file, :name => name}

    self.switch_context(new_context, @@contexts.last)
    @@contexts.push(new_context)

    @@original_histsize = Readline::HISTORY.size
  end

  def self.pop_context
    if @@contexts.empty?
      elog("HistoryManager.pop_context called even when the stack was already empty!")
      return
    end

    old_context = @@contexts.pop
    self.switch_context(@@contexts.last, old_context)

    dlog("HistoryManager.pop_context name: #{name.inspect}")
  end

  def self.switch_context(new_context, old_context)
    if old_context&.fetch(:history_file, nil)
      self.store_history_file(old_context[:history_file], skip: @@original_histsize)
    end

    if new_context&.fetch(:history_file, nil)
      self.load_history_file(new_context[:history_file])@@contexts.last
    else
      self.clear_readline
    end
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

    def store_history_file(history_file, skip: 0)
      cmds = []
      history_diff = Readline::HISTORY.size - skip
      history_diff.times do
        cmds.push(Readline::HISTORY.pop)
      end
      File.open(history_file, 'a+') do |f|
        f.puts(cmds.reverse)
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
