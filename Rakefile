ENV['RDOCOPT'] = "-S -f html -T hanna"

require "rubygems"

require File.dirname(__FILE__) << "/lib/authlogic_ldap/version"

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = 'authlogic-ldap'
    gem.summary = "Extension of the Authlogic library to add LDAP support."
    gem.email = "bjohnson@binarylogic.com"
    gem.homepage = "http://github.com/binarylogic/authlogic_ldap"
    gem.authors = "Ben Johnson of Binary Logic"
    gem.rubyforge_project = "authlogic-ldap"
    gem.add_dependency ["authlogic", "ruby-net-ldap"]
  end
  rescue LoadError
    puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end