module AuthlogicLdap
  module Session
    # Add a simple openid_identifier attribute and some validations for the field.
    def self.included(klass)
      klass.class_eval do
        extend Config
        include Methods
      end
    end
    
    module Config
      # The host of your LDAP server.
      #
      # * <tt>Default:</tt> nil
      # * <tt>Accepts:</tt> String
      def ldap_host(value = nil)
        rw_config(:ldap_host, value)
      end
      alias_method :ldap_host=, :ldap_host
      
      # The port of your LDAP server.
      #
      # * <tt>Default:</tt> 389
      # * <tt>Accepts:</tt> Fixnum, integer
      def ldap_port(value = nil)
        rw_config(:ldap_port, value, 389)
      end
      alias_method :ldap_port=, :ldap_port

      # The login format (the DN for the username) where the given ldap_login
      # will replace the '%s' in the string.
      #
      # Example: "uid=%s,ou=People,o=myserver.institution.edu,o=cp"
      #
      # * <tt>Default:</tt> "%s"
      # * <tt>Accepts:</tt> String
      def ldap_login_format(value = nil)
        rw_config(:ldap_login_format, value, "%s")
      end
      alias_method :ldap_login_format=, :ldap_login_format
      
      # LDAP Encryption configuration settings. Depending on your current LDAP Server
      # you may need to setup encryption.
      #
      # Example: ldap_use_encryption true
      #
      # * <tt>Default:</tt> false
      # * <tt>Accepts:</tt> Boolean
      def ldap_use_encryption(value = nil)
        rw_config(:ldap_use_encryption, value, false)
      end
      alias_method :ldap_use_encryption=, :ldap_use_encryption
      
      
      # Once LDAP authentication has succeeded we need to find the user in the database. By default this just calls the
      # find_by_ldap_login method provided by ActiveRecord. If you have a more advanced set up and need to find users
      # differently specify your own method and define your logic in there.
      #
      # For example, if you allow users to store multiple ldap logins with their account, you might do something like:
      #
      #   class User < ActiveRecord::Base
      #     def self.find_by_ldap_login(login)
      #       first(:conditions => ["#{LdapLogin.table_name}.login = ?", login], :join => :ldap_logins)
      #     end
      #   end
      #
      # * <tt>Default:</tt> :find_by_ldap_login
      # * <tt>Accepts:</tt> Symbol
      def find_by_ldap_login_method(value = nil)
        rw_config(:find_by_ldap_login_method, value, :find_by_ldap_login)
      end
      alias_method :find_by_ldap_login_method=, :find_by_ldap_login_method
      
      # If LDAP authentication has succeeded, but the user does not exist in the database, set this to true to have
      # the the user created in the database. You will need to provide your own method to create the user in the database.
      # By default, the method name is create_with_ldap_data. Use create_with_ldap_data_method to change.
      #
      # For example, to create the user you might do something like:
      #
      #   class User < ActiveRecord::Base
      #     def self.create_with_ldap_data(login, password, ldap_user_data)
      #       self.create(:login       => login,
      #                   :password    => password, :password_confirmation => password,
      #                   :email       => "#{user_data[:mail][0]}",
      #                   :first_name  => "#{user_data[:givenname][0]}",
      #                   :last_name   => "#{user_data[:sn][0]}")
      #     end
      #   end
      #
      # * <tt>Default:</tt> false
      # * <tt>Accepts:</tt> Boolean
      def ldap_create_in_database(value = nil)
        rw_config(:ldap_create_in_database, value, false)
      end
      alias_method :ldap_create_in_database=, :ldap_create_in_database
      
      # LDAP search base for quering for user data.
      #
      # Example: ldap_search_base "ou=People,dc=example,dc=com"
      #
      # * <tt>Default:</tt> 
      # * <tt>Accepts:</tt> String
      def ldap_search_base(value = nil)
        rw_config(:ldap_search_base, value, '')
      end
      alias_method :ldap_search_base=, :ldap_search_base
      
      # LDAP search attribute for quering for user data.
      #
      # Example: ldap_search_attribute 'uid'
      #
      # * <tt>Default:</tt> 'uid'
      # * <tt>Accepts:</tt> String
      def ldap_search_attribute(value = nil)
        rw_config(:ldap_search_attribute, value, 'uid')
      end
      alias_method :ldap_search_attribute=, :ldap_search_attribute
      
      # User creation from LDAP data method. Use this to change the method for creating a user
      # in the local database.
      #
      # Example: create_with_ldap_data_method :create_with_ldap_info
      #
      # * <tt>Default:</tt> :create_with_ldap_data
      # * <tt>Accepts:</tt> Symbol
      def create_with_ldap_data_method(value = nil)
        rw_config(:create_with_ldap_data_method, value, :create_with_ldap_data)
      end
      alias_method :create_with_ldap_data_method=, :create_with_ldap_data_method
    end
    
    
    module Methods
      def self.included(klass)
        klass.class_eval do
          attr_accessor :ldap_login
          attr_accessor :ldap_password
          validate :validate_by_ldap, :if => :authenticating_with_ldap?
        end
        def ldap_use_encryption
          self.class.ldap_use_encryption
        end
      end
      
      # Hooks into credentials to print out meaningful credentials for LDAP authentication.
      def credentials
        if authenticating_with_ldap?
          details = {}
          details[:ldap_login] = send(login_field)
          details[:ldap_password] = "<protected>"
          details
        else
          super
        end
      end
      
      # Hooks into credentials so that you can pass an :ldap_login and :ldap_password key.
      def credentials=(value)
        super
        values = value.is_a?(Array) ? value : [value]
        hash = values.first.is_a?(Hash) ? values.first.with_indifferent_access : nil
        if !hash.nil?
          self.ldap_login = hash[:ldap_login] if hash.key?(:ldap_login)
          self.ldap_password = hash[:ldap_password] if hash.key?(:ldap_password)
        end
      end
      
      private
        def authenticating_with_ldap?
          !ldap_host.blank? && (!ldap_login.blank? || !ldap_password.blank?)
        end
        
        def validate_by_ldap
          errors.add(:ldap_login, I18n.t('error_messages.ldap_login_blank', :default => "can not be blank")) if ldap_login.blank?
          errors.add(:ldap_password, I18n.t('error_messages.ldap_password_blank', :default => "can not be blank")) if ldap_password.blank?
          return if errors.count > 0
          
          ldap = Net::LDAP.new(:host       => ldap_host, 
                               :port       => ldap_port, 
                               :encryption => (:simple_tls if ldap_use_encryption) )

          ldap.auth ldap_login_format % ldap_login, ldap_password
          if ldap.bind
            self.attempted_record = search_for_record(find_by_ldap_login_method, ldap_login)
            if attempted_record.blank?
              if ldap_create_in_database  && (user_data = fetch_user_data(ldap_login, ldap_password))
                self.attempted_record = search_for_record(create_with_ldap_data_method, ldap_login, ldap_password, user_data)
              else
                errors.add(:ldap_login, I18n.t('error_messages.ldap_login_not_found', :default => "does not exist"))
              end
            end
          else
            errors.add_to_base(ldap.get_operation_result.message)
          end
        end
        
        def fetch_user_data(login,password)
          ldap = Net::LDAP.new(:host       => ldap_host, 
                               :port       => ldap_port, 
                               :encryption => (:simple_tls if ldap_use_encryption),
                               :base       => ldap_search_base )
          ldap.authenticate(ldap_login_format % login,password)
          result = ldap.search(:filter => Net::LDAP::Filter.eq(ldap_search_attribute,login))
          result[0] if result
        end
        
        def ldap_host
          self.class.ldap_host
        end
        
        def ldap_port
          self.class.ldap_port
        end
        
        def ldap_login_format
          self.class.ldap_login_format
        end

        def find_by_ldap_login_method
          self.class.find_by_ldap_login_method
        end
        
        def ldap_create_in_database
          self.class.ldap_create_in_database
        end
        
        def ldap_search_base
          self.class.ldap_search_base
        end
        
        def ldap_search_attribute
          self.class.ldap_search_attribute
        end
        
        def create_with_ldap_data_method
          self.class.create_with_ldap_data_method
        end
    end
  end
end
