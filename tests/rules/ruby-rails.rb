class UsersController < ApplicationController
  def index
    # ruleid: vulnscan.ruby.sql-injection
    @users = User.where("name = '#{params[:name]}'")
    # ok: vulnscan.ruby.sql-injection
    @users = User.where(name: params[:name])
    # ok: vulnscan.ruby.sql-injection
    @users = User.where("name = ?", params[:name])
    # ruleid: vulnscan.ruby.sql-injection
    @users = User.order(params[:sort])
    # ok: vulnscan.ruby.sql-injection
    @user = User.find_by(id: params[:id])
    # ruleid: vulnscan.ruby.sql-injection
    ActiveRecord::Base.connection.execute("DELETE FROM notes WHERE id = " + params[:id])
    # ok: vulnscan.ruby.sql-injection
    User.where("age > #{params[:age].to_i}")
  end

  def ping
    host = params[:host]
    # ruleid: vulnscan.ruby.command-injection
    system("ping -c 1 #{host}")
    # ruleid: vulnscan.ruby.command-injection
    out = `nslookup #{host}`
    # ok: vulnscan.ruby.command-injection
    system("ping", "-c", "1", host)
    # ok: vulnscan.ruby.command-injection
    system("ping -c 1 #{Shellwords.escape(host)}")
    # ruleid: vulnscan.ruby.command-injection
    data = open(params[:url]).read
  end

  def export
    # ruleid: vulnscan.ruby.unsafe-reflection
    klass = params[:type].constantize
    # ruleid: vulnscan.ruby.unsafe-reflection
    @report.send(params[:method])
    # ruleid: vulnscan.ruby.code-injection
    eval(params[:formula])
  end

  def download
    # ruleid: vulnscan.ruby.path-traversal
    send_file Rails.root.join("uploads", params[:filename])
    # ok: vulnscan.ruby.path-traversal
    send_file Rails.root.join("uploads", File.basename(params[:filename]))
    # ruleid: vulnscan.ruby.path-traversal
    contents = File.read("/var/data/#{params[:name]}")
  end

  def preview
    # ruleid: vulnscan.ruby.ssrf
    body = Net::HTTP.get(URI(params[:url]))
    # ruleid: vulnscan.ruby.ssrf
    resp = HTTParty.get(params[:webhook])
  end

  def after_login
    # ruleid: vulnscan.ruby.open-redirect
    redirect_to params[:return_to]
    # ok: vulnscan.ruby.open-redirect
    redirect_to root_path
  end

  def show
    # ruleid: vulnscan.ruby.xss
    @bio = params[:bio].html_safe
    # ok: vulnscan.ruby.xss
    @bio2 = sanitize(params[:bio]).html_safe
    # ruleid: vulnscan.ruby.template-injection
    render inline: params[:template]
  end

  def import
    # ruleid: vulnscan.ruby.unsafe-deserialization
    obj = Marshal.load(Base64.decode64(cookies[:state]))
    # ruleid: vulnscan.ruby.unsafe-deserialization
    cfg = YAML.load(request.body.read)
    # ok: vulnscan.ruby.unsafe-deserialization
    cfg2 = YAML.safe_load(request.body.read)
  end

  private

  def user_params
    # ruleid: vulnscan.ruby.mass-assignment
    params.require(:user).permit!
  end
end
