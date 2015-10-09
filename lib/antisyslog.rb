require 'logger'
require 'socket'

FACILITIES = {
  'kern'     => 0,
  'user'     => 1,
  'mail'     => 2,
  'daemon'   => 3,
  'auth'     => 4,
  'syslog'   => 5,
  'lpr'      => 6,
  'news'     => 7,
  'uucp'     => 8,
  'cron'     => 9,
  'authpriv' => 10,
  'ftp'      => 11,
  'ntp'      => 12,
  'audit'    => 13,
  'alert'    => 14,
  'at'       => 15,
  'local0'   => 16,
  'local1'   => 17,
  'local2'   => 18,
  'local3'   => 19,
  'local4'   => 20,
  'local5'   => 21,
  'local6'   => 22,
  'local7'   => 23
}

FACILITY_INDEX = {
  0   => 'kern',
  1   => 'user',
  2   => 'mail',
  3   => 'daemon',
  4   => 'auth',
  5   => 'syslog',
  6   => 'lpr',
  7   => 'news',
  8   => 'uucp',
  9   => 'cron',
  10  => 'authpriv',
  11  => 'ftp',
  12  => 'ntp',
  13  => 'audit',
  14  => 'alert',
  15  => 'at',
  16  => 'local0',
  17  => 'local1',
  18  => 'local2',
  19  => 'local3',
  20  => 'local4',
  21  => 'local5',
  22  => 'local6',
  23  => 'local7'
}

SEVERITIES = {
  'emerg'   => 0,
  'alert'   => 1,
  'crit'    => 2,
  'err'     => 3,
  'warn'    => 4,
  'notice'  => 5,
  'info'    => 6,
  'debug'   => 7 
}

SEVERITY_INDEX = {
  0  => 'emerg',
  1  => 'alert',
  2  => 'crit',
  3  => 'err',
  4  => 'warn',
  5  => 'notice',
  6  => 'info',
  7  => 'debug'
}

class AntisyslogPacket
  attr_reader :facility, :severity, :hostname, :tag
  attr_accessor :time, :content

  def to_s
    assemble
  end

  def assemble()
    unless @hostname and @facility and @severity and @tag
      raise "Could not assemble packet without hostname, tag, facility, and severity"
    end
    "<#{pri}>#{generate_timestamp} #{@hostname} #{@tag}: #{@content}"
  end

  def facility=(f)
    if f.is_a? Integer
      if (0..23).include?(f)
        @facility = f
      else
        raise ArgumentError.new "Facility must be within 0-23"
      end
    elsif f.is_a? String
      if facility = FACILITIES[f]
        @facility = facility
      else
        raise ArgumentError.new "'#{f}' is not a designated facility"
      end
    else
      raise ArgumentError.new "Facility must be a designated number or string"
    end
  end

  def tag=(t)
    unless t && t.is_a?(String) && t.length > 0
      raise ArgumentError, "Tag must not be omitted"
    end
    if t.length > 32
      raise ArgumentError, "Tag must not be longer than 32 characters"
    end
    if t =~ /\s/
      raise ArgumentError, "Tag may not contain spaces"
    end
    if t =~ /[^\x21-\x7E]/
      raise ArgumentError, "Tag may only contain ASCII characters 33-126"
    end

    @tag = t
  end

  def severity=(s)
    if s.is_a? Integer
      if (0..7).include?(s)
        @severity = s
      else
        raise ArgumentError.new "Severity must be within 0-7"
      end
    elsif s.is_a? String
      if severity = SEVERITIES[s]
        @severity = severity
      else
        raise ArgumentError.new "'#{s}' is not a designated severity"
      end
    else
      raise ArgumentError.new "Severity must be a designated number or string"
    end
  end

  def hostname=(h)
    unless h and h.is_a? String and h.length > 0
      raise ArgumentError.new("Hostname may not be omitted")
    end
    if h =~ /\s/
      raise ArgumentError.new("Hostname may not contain spaces")
    end
    if h =~ /[^\x21-\x7E]/
      raise ArgumentError.new("Hostname may only contain ASCII characters 33-126")
    end
    @hostname = h
  end

  def facility_name
    FACILITY_INDEX[@facility]
  end

  def severity_name
    SEVERITY_INDEX[@severity]
  end

  def pri
    (@facility * 8) + @severity
  end

  def pri=(p)
    unless p.is_a? Integer and (0..191).include?(p)
      raise ArgumentError.new "PRI must be a number between 0 and 191"
    end
    @facility = p / 8
    @severity = p - (@facility * 8)
  end

  def generate_timestamp
    time = @time || Time.now
    # The timestamp format requires that a day with fewer than 2 digits have
    # what would normally be a preceding zero, be instead an extra space.
    day = time.strftime("%d")
    day = day.sub(/^0/, ' ') if day =~ /^0\d/
    time.strftime("%b #{day} %H:%M:%S")
  end

  if "".respond_to?(:bytesize)
    def string_bytesize(string)
      string.bytesize
    end
  else
    def string_bytesize(string)
      string.length
    end
  end

  SEVERITIES.each do |k,v|
    define_method("#{k}?") { SEVERITIES[k] == @severity }
  end
end

class AntisyslogSender
  def initialize(remote_hostname, remote_port, options = {})
    @remote_hostname = remote_hostname
    @remote_port     = remote_port
    @whinyerrors     = options[:whinyerrors]
    @protocol        = options[:protocol] || 'tcp'
    @splitlines      = options[:split_lines] || false
    
    @socket = @protocol == 'tcp' ? TCPSocket.new(@remote_hostname, @remote_port) : UDPSocket.new
    @packet = AntisyslogPacket.new

    local_hostname   = options[:local_hostname] || (Socket.gethostname rescue `hostname`.chomp)
    local_hostname   = 'localhost' if local_hostname.nil? || local_hostname.empty?
    @packet.hostname = local_hostname

    @packet.facility = options[:facility] || 'user'
    @packet.severity = options[:severity] || 'notice'
    @packet.tag      = options[:program]  || "#{File.basename($0)}[#{$$}]"
  end

  def send_msg(msg)
    packet = @packet.dup
    packet.content = msg
    if @protocol == 'tcp'
      @socket.send(packet.assemble, 0)
    else
      @socket.send(packet.assemble, 0, @remote_hostname, @remote_port)
    end
  end

  def transmit(message)
    if @splitlines
      message.split(/\r?\n/).each do |line|
        begin
          next if line =~ /^\s*$/
          send_msg(line)
        rescue
          $stderr.puts "#{self.class} error: #{$!.class}: #{$!}\nOriginal message: #{line}"
          raise if @whinyerrors
        end
      end
    else
      begin
        send_msg(message)
      rescue
        $stderr.puts "#{self.class} error: #{$!.class}: #{$!}\nOriginal message: #{message}"
        raise if @whinyerrors
      end
    end
  end

  # Make this act a little bit like an `IO` object
  alias_method :write, :transmit

  def close
    @socket.close
  end
end

module AntiSyslogLogger
  VERSION = '0.0.1'

  def self.new(remote_hostname, remote_port, options = {})
    Logger.new(AntisyslogSender.new(remote_hostname, remote_port, options))
  end
end