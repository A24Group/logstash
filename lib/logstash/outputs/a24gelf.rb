require "logstash/namespace"
require "logstash/outputs/base"

# GELF output. This is most useful if you want to use logstash
# to output events to graylog2.
#
# More information at <http://www.graylog2.org/about/gelf>
class LogStash::Outputs::A24gelf < LogStash::Outputs::Base

  config_name "a24gelf"
  plugin_status "beta"
	
  # graylog2 server address
  config :host, :validate => :string, :required => true

  # graylog2 server port
  config :port, :validate => :number, :default => 12201

  # The GELF chunksize. You usually don't need to change this.
  config :chunksize, :validate => :number, :default => 1420

  # Allow overriding of the gelf 'sender' field. This is useful if you
  # want to use something other than the event's source host as the
  # "sender" of an event. A common case for this is using the application name
  # instead of the hostname.
  config :sender, :validate => :string, :default => "%{@source_host}"

  # The GELF message level. Dynamic values like %{level} are permitted here;
  # useful if you want to parse the 'log level' from an event and use that
  # as the gelf level/severity.
  #
  # Values here can be integers [0..7] inclusive or any of 
  # "debug", "info", "warn", "error", "fatal", "unknown" (case insensitive).
  # Single-character versions of these are also valid, "d", "i", "w", "e", "f",
  # "u"
  config :level, :validate => :array, :default => [ "%{severity}", "INFO" ]

  # The GELF facility. Dynamic values like %{foo} are permitted here; this
  # is useful if you need to use a value from the event as the facility name.
  config :facility, :validate => :string, :default => "logstash-gelf"

	# Field that should not be treated as extra fields the should override the other fields
	config :not_extra_field, :validate => :array, :default => [ ]
	
  # The GELF custom field mappings. GELF supports arbitrary attributes as custom
  # fields. This exposes that. Exclude the `_` portion of the field name
  # e.g. `custom_fields => ['foo_field', 'some_value']
  # sets `_foo_field` = `some_value`
  config :custom_fields, :validate => :hash, :default => {}

  public
  def register
    require "gelf" # rubygem 'gelf'
    option_hash = Hash.new
    #option_hash['level'] = @level
    #option_hash['facility'] = @facility

    #@gelf = GELF::Notifier.new(@host, @port, @chunksize, option_hash)
    @gelf = GELF::Notifier.new(@host, @port, @chunksize)
#		@gelf.collect_file_and_line = false
#		@gelf.level_mapping = {
#			0 => 0,
#			1 => 1,
#			2 => 2,
#			3 => 3,
#			4 => 4,
#			5 => 5,
#			6 => 6,
#			7 => 7
#		}
    # This sets the 'log level' of gelf; since we're forwarding messages, we'll
    # want to forward *all* messages, so set level to 0 so all messages get
    # shipped
    @gelf.level = 0

  end # def register

  public
  def receive(event)
    return unless output?(event)
		
    # We have to make our own hash here because GELF expects a hash
    # with a specific format.
    m = Hash.new
    if event.fields["message"]
      v = event.fields["message"]
      m["short_message"] = (v.is_a?(Array) && v.length == 1) ? v.first : v
    else
      m["short_message"] = event.message
    end

    m["full_message"] = (event.message)
    
		event.fields.each do |name, value|
			next if value == nil
			name = "_id" if name == "id"  # "_id" is reserved, so use "__id"
			if @not_extra_field.include?( name )
				if value.is_a?(Array)
					# collapse single-element arrays, otherwise leave as array
					m["#{name}"] = (value.length == 1) ? value.first : value
				else
					# Non array values should be presented as-is
					# https://logstash.jira.com/browse/LOGSTASH-113
					m["#{name}"] = value
				end
			else 
				if !value.nil?
					if value.is_a?(Array)
						# collapse single-element arrays, otherwise leave as array
						m["_#{name}"] = (value.length == 1) ? value.first : value
					else
						# Non array values should be presented as-is
						# https://logstash.jira.com/browse/LOGSTASH-113
						m["_#{name}"] = value
					end
				end
			end
		end
		
		
		if !m["facility"]
			m["facility"] = event.sprintf(@facility)
		end
		
    if @custom_fields
      @custom_fields.each do |field_name, field_value|
        m["_#{field_name}"] = field_value unless field_name == 'id'
      end
    end

    @logger.debug(["Sending GELF event", m])
    begin
			if !m["timestamp"]
				@gelf.notify!(m, :timestamp => event.unix_timestamp.to_f)
			else 
				@gelf.notify!(m)
			end
    rescue
      @logger.warn("Trouble sending GELF event", :gelf_event => m,
                   :event => event, :error => $!)
    end
  end # def receive
end # class LogStash::Outputs::Gelf