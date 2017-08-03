require 'sinatra'
require 'sinatra/activerecord'
require 'active_record'
require './models/user'
require 'oauth2'
require 'json'
require 'sinatra/partial'
require 'jwt'
require 'sinatra/flash'
require 'pry'
require_relative 'authentificator'

Dotenv.load
register Sinatra::Partial
enable :partial_underscores
set :partial_template_engine, :erb
enable :sessions

LINK_USER_INFO = 'https://www.googleapis.com/userinfo/email?alt=json'.freeze
NOT_AUTHORIZED_ERROR_MESSAGE = 'You are nor autorized'.freeze

signing_key = OpenSSL::PKey.read(ENV['PRV_KEY'])
verify_key = OpenSSL::PKey.read(ENV['PUB_KEY'])

set :signing_key, signing_key
set :verify_key,  verify_key

get '/' do
  @users = User.all

  if authorized?
    @encoded_token = JWT.encode(session[:access_token], settings.signing_key, 'RS256')
    @decoded_token = JWT.decode(@encoded_token, settings.verify_key, true)
  end

  erb :index
end

get '/auth' do
  redirect authentificator.authorize_url
end

get '/oauth2callback' do
  autorize(params)

  redirect '/'
end

get '/logout' do
  session[:access_token] = nil

  redirect '/'
end

post '/create' do
  user = User.create(first_name: params[:username])
  if user.save
    redirect '/'
  else
    flash[:error] = user.errors.full_messages.to_sentence
  end
end

post '/delete' do
  begin
    User.last.delete
  rescue => e
    flash[:error] = "#{e}"
  end

  redirect '/'
end

private

def authorized?
  !session[:access_token].nil?
end

def authentificator
  Authentificator.new
end

def autorize(params)
  access_token = authentificator.fetch_access_token(params[:code])

  session[:access_token] = access_token.token
  session[:email]        = access_token.get(LINK_USER_INFO).parsed
end

def current_user_email
  session[:email]['data']['email']
end
