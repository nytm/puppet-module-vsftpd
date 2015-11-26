require 'spec_helper'

describe 'vsftpd' do
  config_dir = {
    'RedHat'  => '/etc/vsftpd/vsftpd.conf',
    'CentOS'  => '/etc/vsftpd/vsftpd.conf',
    'Amazon'  => '/etc/vsftpd/vsftpd.conf',
    'Fedora'  => '/etc/vsftpd/vsftpd.conf',
    'Debian'  => '/etc/vsftpd.conf',
    'Ubuntu'  => '/etc/vsftpd.conf',
  }
  ['RedHat', 'CentOS', 'Amazon', 'Debian', 'Ubuntu', 'Fedora',
  ].each do |operatingsystem|
    context "with default params on operatingsystem #{operatingsystem}" do
          let :facts do
            {
              :kernel            => 'Linux',
              :operatingsystem   => operatingsystem,
            }
          end
          it { should compile.with_all_deps }

          it { should contain_class('vsftpd')}

          it {
            should contain_package('vsftpd').with({
              'ensure' => 'installed',
            })
          }
          it {
            should contain_file(config_dir[operatingsystem]).with({
              'path' => config_dir[operatingsystem],
              'content' => File.read(fixtures('vsftpd_with_default_params'))
            })
        }
    end
  end
  ['RedHat', 'CentOS', 'Amazon', 'Debian', 'Ubuntu', 'Fedora',
  ].each do |operatingsystem|
    context "with default params changed in hiera on operatingsystem #{operatingsystem}" do
          let :facts do
            {
              :kernel            => 'Linux',
              :operatingsystem   => operatingsystem,
              :specific          => 'vsftpd_without_default_params',
            }
          end
          it { should compile.with_all_deps }

          it { should contain_class('vsftpd')}

          it {
            should contain_package('vsftpd').with({
              'ensure' => 'installed',
            })
          }
          it {
            should contain_file(config_dir[operatingsystem]).with({
              'path' => config_dir[operatingsystem],
              'content' => File.read(fixtures('vsftpd_without_default_params'))
            })
        }
    end
  end
  context "with parameter changed from default value these parameters should exist" do
    fName = '/etc/vsftpd/vsftpd.conf'
    {
      'anon_world_readable_only' => {'default' => 'YES', 'set' => 'NO'},
      'background'               => {'default' => 'YES', 'set' => 'NO'},
      'check_shell'              => {'default' => 'YES', 'set' => 'NO'},
      'chmod_enable'             => {'default' => 'YES', 'set' => 'NO'},
      'deny_email_enable'        => {'default' => 'NO', 'set' => 'YES'},
      'dirlist_enable'           => {'default' => 'YES', 'set' => 'NO'},
      'download_enable'          => {'default' => 'YES', 'set' => 'NO'},
      'dual_log_enable'          => {'default' => 'NO', 'set' => 'YES'},
      'force_dot_files'          => {'default' => 'NO', 'set' => 'YES'},
      'guest_enable'             => {'default' => 'NO', 'set' => 'YES'},
      'lock_upload_files'        => {'default' => 'NO', 'set' => 'YES'},
      'log_ftp_protocol'         => {'default' => 'NO', 'set' => 'YES'},
      'mdtm_write'               => {'default' => 'YES', 'set' => 'NO'},
      'no_anon_password'         => {'default' => 'NO', 'set' => 'YES'},
      'no_log_lock'              => {'default' => 'NO', 'set' => 'YES'},
      'one_process_model'        => {'default' => 'NO', 'set' => 'YES'},
      'passwd_chroot_enable'     => {'default' => 'NO', 'set' => 'YES'},
      'pasv_addr_resolve'        => {'default' => 'NO', 'set' => 'YES'},
      'pasv_enable'              => {'default' => 'YES', 'set' => 'NO'},
      'pasv_promiscuous'         => {'default' => 'NO', 'set' => 'YES'},
      'port_enable'              => {'default' => 'YES', 'set' => 'NO'},
      'port_promiscuous'         => {'default' => 'NO', 'set' => 'YES'},
      'run_as_launching_user'    => {'default' => 'NO', 'set' => 'YES'},
      'secure_email_list_enable' => {'default' => 'NO', 'set' => 'YES'},
      'session_support'          => {'default' => 'NO', 'set' => 'YES'},
      'ssl_enable'               => {'default' => 'NO', 'set' => 'YES'},
      'syslog_enable'            => {'default' => 'NO', 'set' => 'YES'},
      'dirmessage_enable'        => {'default' => 'NO', 'set' => 'YES'},
      'tilde_user_enable'        => {'default' => 'NO', 'set' => 'YES'},
      'use_localtime'            => {'default' => 'NO', 'set' => 'YES'},
      'use_sendfile'             => {'default' => 'YES', 'set' => 'NO'},
      'virtual_use_local_privs'  => {'default' => 'NO', 'set' => 'YES'},
      'accept_timeout'           => {'default' => '60', 'set' => '30'},
      'anon_max_rate'            => {'default' => '0', 'set' => '1'},
      'anon_umask'               => {'default' => '077', 'set' => '022'},
      'connect_timeout'          => {'default' => '60', 'set' => '30'},
      'delay_failed_login'       => {'default' => '1', 'set' => '2'},
      'delay_successful_login'   => {'default' => '0', 'set' => '1'},
      'file_open_mode'           => {'default' => '0666', 'set' => '0777'},
      'ftp_data_port'            => {'default' => '20', 'set' => '21'},
      'local_max_rate'           => {'default' => '0', 'set' => '1'},
      'max_login_fails'          => {'default' => '3', 'set' => '1'},
      'trans_chunk_size'         => {'default' => '0', 'set' => '1'},
      'anon_root'                => {'default' => 'undef', 'set' => '/root/'},
      'cmds_allowed'             => {'default' => 'undef', 'set' => 'PASV,RETR,QUIT'},
      'deny_file'                => {'default' => 'undef', 'set' => '/deny_these_guys'},
      'listen_address'           => {'default' => 'undef', 'set' => '127.0.0.1'},
      'listen_address6'          => {'default' => 'undef', 'set' => '::1'},
      'local_root'               => {'default' => 'undef', 'set' => '/local/root'},
      'pasv_address'             => {'default' => 'undef', 'set' => '127.0.0.1'},
      'secure_chroot_dir'        => {'default' => '/usr/share/empty', 'set' => '/dev/null'},
      'user_config_dir'          => {'default' => 'undef', 'set' => '/etc/vsftpd_user_conf/chris'},
      'user_sub_token'           => {'default' => 'undef', 'set' => '$USER'},
      'vsftpd_log_file'          => {'default' => '/var/log/vsftpd.log', 'set' => '/var/log/ftp_logs.log'},
    }.each do |parameter, values|
      context "#{parameter} set to #{values['set']}" do
        let :params do
          {
            :"#{parameter}" => values['set']
          }
        end

        set = "#{Regexp.escape(values['set'])}"
        default = "#{Regexp.escape(values['default'])}"

        it { should contain_file(fName).with_content(/^#{parameter}=#{set}$/) }
        it { should contain_file(fName).without_content(/^[#]?#{parameter}=#{default}$/) }
      end
    end
    context "defaults with deny_email_enable set to YES" do
      let :params do
        {
          :"deny_email_enable" => 'YES'
        }
      end
      it { should contain_file(fName).with_content(/^deny_email_enable=YES$/) }
      it { should contain_file(fName).with_content(/^banned_email_file=\/etc\/vsftpd\/banned_emails$/) }
    end
    context "defaults with listen set to NO" do
      let :params do
        {
          :"listen" => 'NO'
        }
      end
      it { should contain_file(fName).with_content(/^listen_ipv6=NO$/) }
    end
    context "defaults with listen set to NO and listen_ipv6 set to YES" do
      let :params do
        {
          :"listen" => 'NO',
          :"listen_ipv6" => 'YES'
        }
      end
      it { should contain_file(fName).with_content(/^listen_ipv6=YES$/) }
    end
    context "defaults with secure_email_list_enable set to YES" do
      let :params do
        {
          :"secure_email_list_enable" => 'YES'
        }
      end
      it { should contain_file(fName).with_content(/^email_password_file=\/etc\/vsftpd\/email_passwords$/) }
    end
    context "defaults with guest_enable set to YES" do
      let :params do
        {
          :"guest_enable" => 'YES'
        }
      end
      it { should contain_file(fName).with_content(/^guest_enable=YES$/) }
      it { should contain_file(fName).with_content(/^guest_username=ftp$/) }
    end
    context "defaults with userlist_enable set to YES" do
      let :params do
        {
          :"userlist_enable" => 'YES'
        }
      end
      it { should contain_file(fName).with_content(/^userlist_enable=YES$/) }
      it { should contain_file(fName).with_content(/^userlist_file=\/etc\/vsftpd\/user_list$/) }
      it { should contain_file(fName).with_content(/^userlist_deny=YES$/) }
    end
    context "defaults with dirmessage_enable set to YES" do
      let :params do
        {
          :"dirmessage_enable" => 'YES'
        }
      end
      it { should contain_file(fName).with_content(/^message_file=.message$/) }
    end
    context "defaults with SSL configured" do
      let :params do
        {
          :"ssl_enable" => 'YES'
        }
      end
      it { should contain_file(fName).with_content(/^ssl_enable=YES$/) }
      it { should contain_file(fName).with_content(/^rsa_cert_file=\/usr\/share\/ssl\/certs\/vsftpd.pem$/) }
      it { should contain_file(fName).without_content(/^rsa_private_key_file=.*/) }
      it { should contain_file(fName).without_content(/^dsa_cert_file=.*/) }
      it { should contain_file(fName).without_content(/^dsa_private_key_file=.*/) }
      it { should contain_file(fName).with_content(/^ssl_sslv2=NO$/) }
      it { should contain_file(fName).with_content(/^ssl_sslv3=NO$/) }
      it { should contain_file(fName).with_content(/^ssl_tlsv1=YES$/) }
      it { should contain_file(fName).with_content(/^ssl_request_cert=YES$/) }
      it { should contain_file(fName).with_content(/^force_anon_data_ssl=NO$/) }
      it { should contain_file(fName).with_content(/^force_anon_logins_ssl=NO$/) }
      it { should contain_file(fName).with_content(/^force_local_data_ssl=YES$/) }
      it { should contain_file(fName).with_content(/^force_local_logins_ssl=YES$/) }
      it { should contain_file(fName).with_content(/^ssl_ciphers=DES-CBC3-SHA$/) }
    end
  end
end
