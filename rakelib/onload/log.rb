module Onload
  # Functions for creating coloured logs
  module Log
    COLOUR_CODES = {
      'red' => 91,
      'green' => 92,
      'yellow' => 93,
      'bold' => 1,
    }.freeze

    def self.colourise(colour, message)
      "\e[#{COLOUR_CODES[colour]}m#{message}\e[0m"
    end

    def self.add_header_footer(message)
      '*' * 80 + "\n* " + message + "\n" + '*' * 80
    end

    def self.info(message)
      puts colourise('green', add_header_footer("INFO: #{message}"))
    end

    def self.warning(message)
      puts colourise('yellow', add_header_footer("WARNING: #{message}"))
    end

    def self.error(message)
      puts colourise('red', add_header_footer("ERROR: #{message}"))
    end
  end
end
