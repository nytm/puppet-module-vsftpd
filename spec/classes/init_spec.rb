require 'spec_helper'

describe 'vsftpd' do

  config_matrix = {
    'RedHat' => {
      'config_file'         => '/etc/vsftpd/vsftpd.conf',
      'chroot_dir'          => '/usr/share/empty',
      'with_def_params'     => 'vsftpd_with_default_params_rpm_based',
      'with_nondef_params'  => 'vsftpd_without_default_params_rpm_based',
    },
    'CentOS' => {
      'config_file'         => '/etc/vsftpd/vsftpd.conf',
      'chroot_dir'          => '/usr/share/empty',
      'with_def_params'     => 'vsftpd_with_default_params_rpm_based',
      'with_nondef_params'  => 'vsftpd_without_default_params_rpm_based',
    },
    'Amazon' => {
      'config_file'         => '/etc/vsftpd/vsftpd.conf',
      'chroot_dir'          => '/usr/share/empty',
      'with_def_params'     => 'vsftpd_with_default_params_rpm_based',
      'with_nondef_params'  => 'vsftpd_without_default_params_rpm_based',
    },
    'Fedora' => {
      'config_file'         => '/etc/vsftpd/vsftpd.conf',
      'chroot_dir'          => '/usr/share/empty',
      'with_def_params'     => 'vsftpd_with_default_params_rpm_based',
      'with_nondef_params'  => 'vsftpd_without_default_params_rpm_based',
    },
    'Debian' => {
      'config_file'         => '/etc/vsftpd.conf',
      'chroot_dir'          => '/var/run/vsftpd/empty',
      'with_def_params'     => 'vsftpd_with_default_params_apt_based',
      'with_nondef_params'  => 'vsftpd_without_default_params_apt_based',
    },
    'Ubuntu' => {
      'config_file'         => '/etc/vsftpd.conf',
      'chroot_dir'          => '/var/run/vsftpd/empty',
      'with_def_params'     => 'vsftpd_with_default_params_apt_based',
      'with_nondef_params'  => 'vsftpd_without_default_params_apt_based',
    }
  }

  config_matrix.each do |operatingsystem, data|
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
          it do
            is_expected.to contain_file(config_matrix[operatingsystem]['chroot_dir']).with({
              'ensure' => 'directory',
              'owner'  => 'root',
              'group'  => 'root',
              'mode'   => '0555',
            })
          end
          it {
            should contain_file(config_matrix[operatingsystem]['config_file']).with({
              'content' => File.read(fixtures(config_matrix[operatingsystem]['with_def_params']))
            })
        }
    end
  end
  config_matrix.each do |operatingsystem, data|
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
          it do
            is_expected.to contain_file(config_matrix[operatingsystem]['chroot_dir']).with({
              'ensure' => 'directory',
              'owner'  => 'root',
              'group'  => 'root',
              'mode'   => '0555',
            })
          end
          it {
            should contain_file(config_matrix[operatingsystem]['config_file']).with({
              'content' => File.read(fixtures(config_matrix[operatingsystem]['with_nondef_params']))
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
    context "defaults with allow_writeable_chroot set to YES" do
      let :params do
        {
          :"allow_writeable_chroot" => 'YES'
        }
      end
      it { should contain_file(fName).with_content(/^allow_writeable_chroot=YES$/) }
    end
  end
  describe 'variable type and content validations' do
    # set needed custom facts and variables
    let(:facts) { {
      :osfamily => 'RedHat',
    } }
    let(:validation_params) { {
#      :param => 'value',
    } }

    validations = {
      'string' => {
        :name    => ['guest_username', 'pam_service_name', 'ftp_username', 'chown_username', 'nopriv_user', 'message_file', 'ssl_ciphers', 'xferlog_file', 'vsftpd_log_file', 'userlist_file', 'chroot_list_file', 'banned_email_file', 'email_password_file', 'rsa_cert_file', 'ftpd_banner', 'hide_file', 'banner_file', 'anon_root', 'cmds_allowed', 'deny_file', 'dsa_cert_file', 'dsa_private_key_file', 'listen_address', 'listen_address6', 'local_root', 'pasv_address', 'rsa_private_key_file', 'user_config_dir', 'user_sub_token'],
        :valid   => ['string_word'],
        :invalid => [['array'],a={'ha'=>'sh'},true,false],
        :message => 'is not a string',
      },
      'regex_file_mode' => {
        :name    => ['file_open_mode'],
        :valid   => ['0755','0644','0242'],
        :invalid => ['invalid','755',0755,'0980',['array'],a={'ha'=>'sh'},3,2.42,true,false,nil],
        :message => 'must be a valid four digit mode in octal notation',
      },
      'regex_umask_mode' => {
        :name    => ['anon_umask', 'local_umask'],
        :valid   => ['077','066','255'],
        :invalid => ['invalid','999', 0755,'0980',3,2.42,nil],
        :message => '(must be a valid three digit mode in octal notation|Error while evaluating a Function Call)',
      },
      'port_number' => {
        :name    => ['ftp_data_port', 'listen_port', 'pasv_min_port', 'pasv_max_port'],
        :valid   => [22],
        :invalid => [65555, -100, -422],
        :message => '(Expected first argument to be an Integer or Array|Expected [-]?\d+ to be (smaller|greater) or equal to (0|65535))',
      },
      'string_yes_no' => {
        :name    => ['allow_writeable_chroot', 'anonymous_enable', 'local_enable', 'write_enable', 'anon_upload_enable', 'anon_mkdir_write_enable', 'dirmessage_enable', 'xferlog_enable', 'connect_from_port_20', 'chown_uploads', 'xferlog_std_format', 'async_abor_enable', 'ascii_upload_enable', 'ascii_download_enable', 'chroot_local_user', 'chroot_list_enable', 'ls_recurse_enable', 'listen', 'userlist_enable', 'userlist_deny', 'tcp_wrappers', 'hide_ids', 'setproctitle_enable', 'text_userdb_names', 'ssl_request_cert', 'anon_other_write_enable', 'anon_world_readable_only', 'background', 'check_shell', 'chmod_enable', 'deny_email_enable', 'dirlist_enable', 'download_enable', 'dual_log_enable', 'force_dot_files', 'force_anon_data_ssl', 'force_anon_logins_ssl', 'force_local_data_ssl', 'force_local_logins_ssl', 'guest_enable', 'listen_ipv6', 'lock_upload_files', 'log_ftp_protocol', 'mdtm_write', 'no_anon_password', 'no_log_lock', 'one_process_model', 'passwd_chroot_enable', 'pasv_addr_resolve', 'pasv_enable', 'pasv_promiscuous', 'port_enable', 'port_promiscuous', 'reverse_lookup_enable', 'run_as_launching_user', 'secure_email_list_enable', 'session_support', 'ssl_enable', 'ssl_sslv2', 'ssl_sslv3', 'ssl_tlsv1', 'syslog_enable', 'tilde_user_enable', 'use_localtime', 'use_sendfile', 'virtual_use_local_privs'],
        :valid   => ['YES', 'NO'],
        :invalid => [['array'],a={'ha'=>'sh'},true,false],
        :message => 'Must be either \'YES\' or \'NO\'',
      },
    }

    validations.sort.each do |type,var|
      var[:name].each do |var_name|

        var[:valid].each do |valid|
          context "with #{var_name} (#{type}) set to valid #{valid} (as #{valid.class})" do
            let(:params) { validation_params.merge({:"#{var_name}" => valid, }) }
            it { should compile }
          end
        end

        var[:invalid].each do |invalid|
          context "with #{var_name} (#{type}) set to invalid #{invalid} (as #{invalid.class})" do
            let(:params) { validation_params.merge({:"#{var_name}" => invalid, }) }
            it 'should fail' do
              expect {
                should contain_class(subject)
              }.to raise_error(Puppet::Error,/#{var[:message]}/)
            end
          end
        end

      end # var[:name].each
    end # validations.sort.each
  end # describe 'variable type and content validations'
end
