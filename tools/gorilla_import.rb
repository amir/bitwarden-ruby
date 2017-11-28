#!/usr/bin/env ruby
#
# Copyright (c) 2017 amir saeid <amir@glgdgt.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

#
# Read a given Gorilla csv file, ask for the given user's master password,
# then lookup the given user in the bitwarden-ruby SQLite database and
# its key.  Each 1Password password entry is encrypted and inserted into
# into the database.
#
# No check is done to eliminate duplicates, so this is best used on a fresh
# bitwarden-ruby installation after creating a new account.
#

require File.realpath(File.dirname(__FILE__) + "/../lib/bitwarden_ruby.rb")
require "getoptlong"

def usage
  puts "usage: #{$0} -f data.csv -u user@example.com"
  exit 1
end

username = nil
file = nil

begin
  GetoptLong.new(
    [ "--file", "-f", GetoptLong::REQUIRED_ARGUMENT ],
    [ "--user", "-u", GetoptLong::REQUIRED_ARGUMENT ],
  ).each do |opt,arg|
    case opt
    when "--file"
      file = arg

    when "--user"
      username = arg
    end
  end

rescue GetoptLong::InvalidOption
  usage
end

if !file || !username
  usage
end

@u = User.find_by_email(username)
if !@u
  raise "can't find existing User record for #{username.inspect}"
end

print "master password for #{@u.email}: "
system("stty -echo")
password = STDIN.gets.chomp
system("stty echo")
print "\n"

if !@u.has_password_hash?(Bitwarden.hashPassword(password, username))
  raise "master password does not match stored hash"
end

@master_key = Bitwarden.makeKey(password, @u.email)

def encrypt(str)
  @u.encrypt_data_with_master_password_key(str, @master_key)
end

to_save = {}
skipped = 0

File.read(file).split("\n").each_with_index do |line, index|
  next if index == 0  
  fields = line.split(",")

  c = Cipher.new
  c.user_uuid = @u.uuid
  c.type = Cipher::TYPE_LOGIN

  cdata = {
    "Name" => encrypt(fields[2].blank? ? "--" : fields[2]),
  }

  unless fields[3].empty?
    cdata["Uri"] = encrypt(fields[3])
  end

  unless fields[4].empty?
    cdata["Username"] = encrypt(fields[4])
  end

  unless fields[5].empty?
    cdata["Password"] = encrypt(fields[5])
  end

  unless fields[6].nil?
    cdata["Notes"] = encrypt(fields[6])
  end

  puts cdata

  c.data = cdata.to_json

  to_save[c.type] ||= []
  to_save[c.type].push c
end

to_save.each do |k,v|
   puts "#{sprintf("% 4d", v.count)} #{Cipher.type_s(k)}" <<
    (v.count == 1 ? "" : "s")
end

imp = 0

Cipher.transaction do
  to_save.each do |k, v|
    v.each do |c|
      if !c.save
        raise "failed saving #{c.inspect}"
      end

      imp += 1
    end
  end
end

puts "successfully imported #{imp} item#{imp == 1 ? "" : "s"}"
