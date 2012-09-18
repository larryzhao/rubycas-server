require 'casserver/authenticators/sql'

require 'bcrypt'

# Essentially the same as the standard SQL authenticator but assumes that
# BCrypt has been used to encrypt the password. If you're using
# has_secure_password, then this is probably for you.
class CASServer::Authenticators::SQLDevise < CASServer::Authenticators::SQL

  protected

  def matching_users 
    results = user_model.find(:all, :conditions => ["#{username_column} = ?", @username])
    results.select { |user| 
      bcrypt   = ::BCrypt::Password.new(user.encrypted_password)
      password = ::BCrypt::Engine.hash_secret("#{@password}", bcrypt.salt)  # how to get pepper?
      password == user.encrypted_password
    }
  end

end
