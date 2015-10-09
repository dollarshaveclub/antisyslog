antisyslog
==========

Rails logger forked from [remote_syslog_logger](https://github.com/papertrail/remote_syslog_logger) and [syslog_protocol](https://github.com/eric/syslog_protocol).

- Transmit via TCP by default (toggle via ``protocol`` option)
- No line splitting (use ``split_lines`` to override)
- No message truncation (not RFC-compliant)

Usage:
------

```ruby
config.logger = AntiSyslogLogger.new('syslog.domain.com', 514, :protocol => 'udp', :split_lines => true, :program => "rails-#{RAILS_ENV}", :local_hostname => "optional_hostname")
```
