# -*- coding: binary -*-

module Msf
module Ui
module Console

class HistoryManager
 

  @@contexts = []

  def self.push_context(history_file)
    if @@contexts.length > 1
      self.pop_context()
    end
    @@contexts.push(history_file)
    self.set_history_file(history_file)
  end

  def self.pop_context()
    if @@contexts.empty?
      return
    end
    cmds = []
    history_diff = Readline::HISTORY.size - @@original_histsize
    history_diff.times do 
      cmds.push(Readline::HISTORY.pop)
    end
    history_file = @@contexts.pop
    File.open(history_file, "a+") { |f| 
      f.puts(cmds.reverse) }
    self.clear_readline
  end


  def self.set_history_file(history_file)
    self.clear_readline
    if File.exist?(history_file)
      File.readlines(history_file).each { |e|
        Readline::HISTORY << e.chomp
      }
      @@original_histsize = Readline::HISTORY.size
    else
      @@original_histsize = 0
    end
  end

  def self.clear_readline
    Readline::HISTORY.length.times {Readline::HISTORY.pop}
  end
end

end
end
end
