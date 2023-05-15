#!/usr/bin/env perl

#  Copyright (C) 2011 DeNA Co.,Ltd.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#  Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

package MHA::MasterMonitor;

use strict;
use warnings FATAL => 'all';
use Carp qw(croak);
use English qw(-no_match_vars);
use Getopt::Long qw(:config pass_through);
use Pod::Usage;
use Log::Dispatch;
use Log::Dispatch::Screen;
use MHA::Config;
use MHA::ServerManager;
use MHA::HealthCheck;
use MHA::FileStatus;
use MHA::SSHCheck;
use MHA::ManagerConst;
use MHA::ManagerUtil;
use MHA::BinlogManager;
use File::Basename;

my $g_global_config_file = $MHA::ManagerConst::DEFAULT_GLOBAL_CONF;
my $g_config_file;
my $g_check_only;
my $g_check_repl_health;
my $g_seconds_behind_master = 30;
my $g_monitor_only;
my $g_workdir;
my $g_interactive = 1;
my $g_logfile;
my $g_wait_on_monitor_error = 0;
my $g_skip_ssh_check;
my $g_ignore_fail_on_start = 0;
my $_master_node_version;
my $_server_manager;
my $_master_ping;
my $RETRY = 100;
my $_status_handler;
my $log;

sub exit_by_signal {
  $log->info("Got terminate signal. Exit.");
  eval {
    MHA::NodeUtil::drop_file_if( $_status_handler->{status_file} )
      unless ($g_check_only);
    $_server_manager->disconnect_all() if ($_server_manager);
    $_master_ping->disconnect_if()     if ($_master_ping);
  };
  if ($@) {
    $log->error("Got Error: $@");
    undef $@;
  }
  exit 1;
}

sub get_binlog_check_command {
  my $target     = shift;
  my $use_prefix = shift;

  # this file is not created. just checking directory path
  my $workfile = "$target->{remote_workdir}/save_binary_logs_test";
  my $command =
"save_binary_logs --command=test --start_pos=4 --binlog_dir=$target->{master_binlog_dir} --output_file=$workfile --manager_version=$MHA::ManagerConst::VERSION";
  my $file;
  if ( $target->{File} ) {
    $file = $target->{File};
  }
  else {
    my @alive_slaves = $_server_manager->get_alive_slaves();
    my $slave        = $alive_slaves[0];
    $slave->current_slave_position();
    $file = $slave->{Master_Log_File};
  }
  if ($use_prefix) {
    my ( $binlog_prefix, $number ) =
      MHA::BinlogManager::get_head_and_number($file);
    $command .= " --binlog_prefix=$binlog_prefix";
  }
  else {
    $command .= " --start_file=$file";
  }

  unless ( $target->{handle_raw_binlog} ) {
    my $oldest_version = $_server_manager->get_oldest_version();
    $command .= " --oldest_version=$oldest_version ";
  }
  if ( $target->{log_level} eq "debug" ) {
    $command .= " --debug ";
  }
  return $command;
}

sub check_master_ssh_env($) {
  my $target = shift;
  $log->info(
    "Checking SSH publickey authentication settings on the current master..");

  my $ssh_reachable;
  if (
    MHA::HealthCheck::ssh_check_simple(
      $target->{ssh_user}, $target->{ssh_host},
      $target->{ssh_ip},   $target->{ssh_port},
      $target->{logger},   $target->{ssh_connection_timeout}
    )
    )
  {
    $ssh_reachable = 0;
  }
  else {
    $ssh_reachable = 1;
  }
  if ( $ssh_reachable && !$target->{has_gtid} ) {
    $_master_node_version =
      MHA::ManagerUtil::get_node_version( $log, $target->{ssh_user},
      $target->{ssh_host}, $target->{ssh_ip}, $target->{ssh_port} );
    if ( !$_master_node_version ) {
      $log->error(
"Failed to get MHA node version on the current master even though current master is reachable via SSH!"
      );
      croak;
    }
    $log->info("Master MHA Node version is $_master_node_version.");
  }
  return $ssh_reachable;
}

sub check_binlog($) {
  my $target = shift;
  $log->info(
    sprintf( "Checking recovery script configurations on %s..",
      $target->get_hostinfo() )
  );
  my $ssh_user_host = $target->{ssh_user} . '@' . $target->{ssh_ip};
  my $command       = get_binlog_check_command($target);
  $log->info("  Executing command: $command ");
  $log->info(
    "  Connecting to $ssh_user_host($target->{ssh_host}:$target->{ssh_port}).. "
  );
  my ( $high, $low ) =
    MHA::ManagerUtil::exec_ssh_cmd( $ssh_user_host, $target->{ssh_port},
    $command, $g_logfile );
  if ( $high ne '0' || $low ne '0' ) {
    $log->error("Binlog setting check failed!");
    return 1;
  }
  $log->info("Binlog setting check done.");
  return 0;
}

sub check_slave_env() {
  my @alive_servers = $_server_manager->get_alive_slaves();
  $log->info(
"Checking SSH publickey authentication and checking recovery script configurations on all alive slave servers.."
  );
  foreach my $s (@alive_servers) {
    my $ssh_user_host = $s->{ssh_user} . '@' . $s->{ssh_ip};
    my $command =
"apply_diff_relay_logs --command=test --slave_user=$s->{escaped_user} --slave_host=$s->{hostname} --slave_ip=$s->{ip} --slave_port=$s->{port} --workdir=$s->{remote_workdir} --target_version=$s->{mysql_version} --manager_version=$MHA::ManagerConst::VERSION";
    if ( $s->{client_bindir} ) {
      $command .= " --client_bindir=$s->{client_bindir}";
    }
    if ( $s->{client_libdir} ) {
      $command .= " --client_libdir=$s->{client_libdir}";
    }
    if ( $s->{relay_log_info_type} eq "TABLE" ) {
      $command .=
" --relay_dir=$s->{relay_dir} --current_relay_log=$s->{current_relay_log} ";
    }
    else {
      $command .= " --relay_log_info=$s->{relay_log_info} ";
      $command .= " --relay_dir=$s->{datadir} ";
    }
    if ( $s->{log_level} eq "debug" ) {
      $command .= " --debug ";
    }
    if ($MHA::ManagerConst::USE_SSH_OPTIONS) {
      $command .= " --ssh_options='$MHA::NodeConst::SSH_OPT_ALIVE' ";
    }
    $log->info("  Executing command : $command --slave_pass=xxx");

    if ( $s->{escaped_password} ne "" ) {
      $command .= " --slave_pass=$s->{escaped_password}";
    }
    $log->info(
      "  Connecting to $ssh_user_host($s->{ssh_host}:$s->{ssh_port}).. ");
    my ( $high, $low ) =
      MHA::ManagerUtil::exec_ssh_cmd( $ssh_user_host, $s->{ssh_port}, $command,
      $g_logfile );
    if ( $high ne '0' || $low ne '0' ) {
      $log->error("Slaves settings check failed!");
      return 1;
    }
  }
  $log->info("Slaves settings check done.");
  return 0;
}

sub check_scripts($) {
  my $current_master = shift;
  if ( $current_master->{master_ip_failover_script} ) {
    my $command =
"$current_master->{master_ip_failover_script} --command=status --ssh_user=$current_master->{ssh_user} --orig_master_host=$current_master->{hostname} --orig_master_ip=$current_master->{ip} --orig_master_port=$current_master->{port}";
    $command .= $current_master->get_ssh_args_if( 1, "orig", 1 );
    $log->info("Checking master_ip_failover_script status:");
    $log->info("  $command");
    my ( $high, $low ) = MHA::ManagerUtil::exec_system( $command, $g_logfile );
    if ( $high == 0 && $low == 0 ) {
      $log->info(" OK.");
    }
    else {
      $log->error(
" Failed to get master_ip_failover_script status with return code $high:$low."
      );
      croak;
    }
  }
  else {
    $log->warning("master_ip_failover_script is not defined.");
  }

  if ( $current_master->{shutdown_script} ) {
    my $command =
"$current_master->{shutdown_script} --command=status --ssh_user=$current_master->{ssh_user} --host=$current_master->{hostname} --ip=$current_master->{ip}";
    $command .= $current_master->get_ssh_args_if( 1, "shutdown", 1 );
    $log->info("Checking shutdown script status:");
    $log->info("  $command");
    my ( $high, $low ) = MHA::ManagerUtil::exec_system( $command, $g_logfile );
    if ( $high == 0 && $low == 0 ) {
      $log->info(" OK.");
    }
    else {
      $log->error(" Failed to get power status with return code $high:$low.");
      croak;
    }
  }
  else {
    $log->warning("shutdown_script is not defined.");
  }
}

sub check_binlog_servers {
  my $binlog_server_ref = shift;
  my $log               = shift;
  my @binlog_servers    = @$binlog_server_ref;
  if ( $#binlog_servers >= 0 ) {
    MHA::ServerManager::init_binlog_server( $binlog_server_ref, $log );
    foreach my $server (@binlog_servers) {
      if ( check_binlog($server) ) {
        $log->error("Binlog server configuration failed.");
        croak;
      }
    }
  }
}

sub wait_until_master_is_unreachable() {
  my ( @servers_config, @servers, @dead_servers, @alive_servers, @alive_slaves,
    $current_master, $ret, $ssh_reachable );
  my $func_rc = 1;
  eval {
    $g_logfile = undef if ($g_check_only);
    # 初始化日志
    $log = MHA::ManagerUtil::init_log($g_logfile);
    # 检查配置文件是否存在 ，不存在的话 报错并退出
    unless ( -f $g_config_file ) {
      $log->error("Configuration file $g_config_file not found!");
      croak;
    }

    # 从配置文件中读取配置
    my ( $sc_ref, $binlog_server_ref ) = new MHA::Config(
      logger     => $log,
      globalfile => $g_global_config_file,
      file       => $g_config_file
    )->read_config();
    @servers_config = @$sc_ref;

    # 如果变量 $g_logfile没有定义 ，也不是检查模式 ，然后servers_config数组中的第一个元素中的manager_log键 有值 ，则定义g_logfile的值为$servers_config[0]->{manager_log}
    if ( !$g_logfile && !$g_check_only && $servers_config[0]->{manager_log} ) {
      $g_logfile = $servers_config[0]->{manager_log};
    }

    # 重新初始化日志，因为现在读取了配置文件，所以可以读取到 日志文件的名称 和 日志输出级别。后面输出的日志都可以记录到文件中
    $log =
      MHA::ManagerUtil::init_log( $g_logfile, $servers_config[0]->{log_level} );

    # 输出MHA 的 版本
    $log->info("MHA::MasterMonitor version $MHA::ManagerConst::VERSION.");

    # 如果变量 $g_workdir 不存在 ，
    unless ($g_workdir) {
      # 如果$servers_config[0]->{manager_workdir} (配置文件中的配置项manager_workdir) 存在 ，则赋值给 $g_workdir
      if ( $servers_config[0]->{manager_workdir} ) {
        $g_workdir = $servers_config[0]->{manager_workdir};
      }
      else {
        # $servers_config[0]->{manager_workdir}没有值 (配置文件中没有配置项manager_workdir) ，则使用"/var/tmp" 作为MHA的工作目录
        $g_workdir = "/var/tmp";
      }
    }
    # 检查 node 的版本 和 manager的 版本 ，如果 $node_version < $MHA::ManagerConst::NODE_MIN_VERSION（0.54）  则退出
    MHA::ManagerUtil::check_node_version($log);
    MHA::NodeUtil::check_manager_version($MHA::ManagerConst::VERSION);

    # 创建MHA的工作目录
    MHA::NodeUtil::create_dir_if($g_workdir);
    # 如果不是检查模式 ，创建实例的状态标识文件 例如 app1.master.health
    unless ($g_check_only) {
      $_status_handler =
        new MHA::FileStatus( conffile => $g_config_file, dir => $g_workdir );
      $_status_handler->init();
      # 如果状态标识文件存在 在告警 并且 删除状态标识文件
      if ( -f $_status_handler->{status_file} ) {
        $log->warning(
"$_status_handler->{status_file} already exists. You might have killed manager with SIGKILL(-9), may run two or more monitoring process for the same application, or use the same working directory. Check for details, and consider setting --workdir separately."
        );
        MHA::NodeUtil::drop_file_if( $_status_handler->{status_file} );
      }
      # 更新状态标识文件中的状态
      $_status_handler->update_status(
        $MHA::ManagerConst::ST_INITIALIZING_MONITOR_S);
    }

    $_server_manager = new MHA::ServerManager( servers => \@servers_config );
    $_server_manager->set_logger($log);
    # 连接配置文件中的所有的实例 并且根据实例状态分成不同数组
    $_server_manager->connect_all_and_read_server_status();
    # 宕机的实例数组
    @dead_servers  = $_server_manager->get_dead_servers();
    # 存活的实例数组
    @alive_servers = $_server_manager->get_alive_servers();
    # 存活的从实例数组
    @alive_slaves  = $_server_manager->get_alive_slaves();
    # 打印到屏幕 输出到日志中
    $log->info("Dead Servers:");
    $_server_manager->print_dead_servers();
    $log->info("Alive Servers:");
    $_server_manager->print_alive_servers();
    $log->info("Alive Slaves:");
    $_server_manager->print_alive_slaves();
    $_server_manager->print_failed_slaves_if();
    $_server_manager->print_unmanaged_slaves_if();
    # 获取目前存活的主库
    $current_master = $_server_manager->get_current_alive_master();

    # 没有存活的主库
    unless ($current_master) {
      # 交互模式
      if ($g_interactive) {
        # 打印交互信息
        print "Master is not currently alive. Proceed? (yes/NO): ";
        my $ret = <STDIN>;
        chomp($ret);
        die "abort" if ( lc($ret) !~ /^y/ );
      }
    }

    # 检查存活从实例的配置 有4项检查 。检查通过返回0 。
    if (
      $_server_manager->validate_slaves(
        $servers_config[0]->{check_repl_filter},
        $current_master
      )
      )
    {
      $log->error("Slave configurations is not valid.");
      croak;
    }
    # 获取不能成为主库的实例 bad  (有5种情况，详情见以下函数)
    my @bad = $_server_manager->get_bad_candidate_masters();

    # 如果bad 数组包含所有的存活的从实例 数组 ，则报错退出
    if ( $#alive_slaves <= $#bad ) {
      $log->error( "None of slaves can be master. Check failover "
          . "configuration file or log-bin settings in my.cnf" );
      croak;
    }
    $_server_manager->check_repl_priv();

    # 如果不是GTID模式 则需要检查SSH 和 node的版本 （node package是否安装 ，node version 是否高于等于manage version）
    if ( !$_server_manager->is_gtid_auto_pos_enabled() ) {
      $log->info("GTID (with auto-pos) is not supported");
      MHA::SSHCheck::do_ssh_connection_check( \@alive_servers, $log,
        $servers_config[0]->{log_level}, $g_workdir )
        unless ($g_skip_ssh_check);
      $log->info("Checking MHA Node version..");
      foreach my $slave (@alive_slaves) {
        MHA::ManagerUtil::check_node_version(
          $log,             $slave->{ssh_user}, $slave->{ssh_host},
          $slave->{ssh_ip}, $slave->{ssh_port}
        );
      }
      $log->info(" Version check ok.");
    }
    # 如果是GTID模式 则跳过所有的 SSH检查和 node package检查
    else {
      $log->info(
"GTID (with auto-pos) is supported. Skipping all SSH and Node package checking."
      );
      # GTID模式需要检查binlog 包括 SSH 和 使用以下命令检查
      #  "save_binary_logs --command=test --start_pos=4 --binlog_dir=$target->{master_binlog_dir} --output_file=$workfile --manager_version=$MHA::ManagerConst::VERSION";
      check_binlog_servers( $binlog_server_ref, $log );
    }

    unless ($current_master) {
      $log->info("Getting current master (maybe dead) info ..");
      $current_master = $_server_manager->get_orig_master();
      if ( !$current_master ) {
        $log->error("Failed to get current master info!");
        croak;
      }
      $log->info(
        sprintf( "Identified master is %s.", $current_master->get_hostinfo() )
      );
    }
    $_server_manager->validate_num_alive_servers( $current_master,
      $g_ignore_fail_on_start );
    # 检查主库的 SSH node package
    if ( check_master_ssh_env($current_master) ) {
      # 如果不是GTID模式 并且 使用命令 save_binary_logs 检查binlog 失败 ，则退出
      if ( !$_server_manager->is_gtid_auto_pos_enabled()
        && check_binlog($current_master) )
      {
        $log->error("Master configuration failed.");
        croak;
      }
    }
    # 更新状态标识文件里的内容 例如 （ 116517	0:PING_OK	master:10.79.23.45  ）
    $_status_handler->set_master_host( $current_master->{hostname} )
      unless ($g_check_only);
    # 如果不是GTID模式 并且检查从实例的 使用命令 ： apply_diff_relay_logs 失败 则退出
    if ( !$_server_manager->is_gtid_auto_pos_enabled() && check_slave_env() ) {
      $log->error("Slave configuration failed.");
      croak;
    }
    # 打印当前的主从实例 和 拓扑结构
    $_server_manager->print_servers_ascii($current_master);
    # 如果设置允许的主从延迟 检查延迟状况
    $_server_manager->check_replication_health($g_seconds_behind_master)
      if ($g_check_repl_health);
    # 检查脚本  master_ip_failover_script} --command=status  和  {shutdown_script} --command=status。 详细命令可以看下面的函数
    check_scripts($current_master);
    # 断开连接
    $_server_manager->disconnect_all();
    $func_rc = 0;
  };
  # 在 Perl 语言中，"$@" 是一个特殊变量，用于捕获 eval 语句执行时产生的错误信息。
  # 在使用 eval 语句时，如果被执行的代码块中发生了异常，$@ 就会被设置为错误信息。
  # 如果 eval 执行成功，$@ 就会被设置为一个空字符串。在程序中，通常会使用 $@ 来判断 eval 语句是否执行成功，或者捕获 eval 语句中发生的错误信息。

  if ($@) {
    $log->error("Error happened on checking configurations. $@") if ($log);
    undef $@;
    return $func_rc;
  }
  return $func_rc if ($g_check_only);

  # master ping. This might take hours/days/months.. 进入到主库监控的环节 这个时间可能很久 。
  # 将$func_rc 设置为1  这个应该是一个状态码 或者返回状态量
  $func_rc = 1;
  eval {
    my $ssh_check_command;
    # 如果不是GTID模式 并且 $_master_node_version 有值  $_master_node_version >=0.53
    if (!$_server_manager->is_gtid_auto_pos_enabled()
      && $_master_node_version
      && $_master_node_version >= 0.53 )
    {
      $ssh_check_command = get_binlog_check_command( $current_master, 1 );
    }
    else {
      $ssh_check_command = "exit 0";
    }
    # 打印检查命令
    $log->debug("SSH check command: $ssh_check_command");

    # 主实例健康检查
    $_master_ping = new MHA::HealthCheck(
      user                   => $current_master->{user},
      password               => $current_master->{password},
      ip                     => $current_master->{ip},
      hostname               => $current_master->{hostname},
      port                   => $current_master->{port},
      interval               => $current_master->{ping_interval},
      ssh_user               => $current_master->{ssh_user},
      ssh_host               => $current_master->{ssh_host},
      ssh_ip                 => $current_master->{ssh_ip},
      ssh_port               => $current_master->{ssh_port},
      ssh_connection_timeout => $current_master->{ssh_connection_timeout},
      ssh_check_command      => $ssh_check_command,
      status_handler         => $_status_handler,
      logger                 => $log,
      logfile                => $g_logfile,
      workdir                => $g_workdir,
      ping_type              => $current_master->{ping_type},
    );
    # 检查间隔，默认3秒
    $log->info(
      sprintf( "Set master ping interval %d seconds.",
        $_master_ping->get_ping_interval() )
    );
    # 如果设置了二路检查脚本
    if ( $current_master->{secondary_check_script} ) {
      $_master_ping->set_secondary_check_script(
        $current_master->{secondary_check_script} );
      $log->info(
        sprintf( "Set secondary check script: %s",
          $_master_ping->get_secondary_check_script() )
      );
    }
    else {
      # 强烈建议设置了二路检查脚本
      $log->warning(
"secondary_check_script is not defined. It is highly recommended setting it to check master reachability from two or more routes."
      );
    }

    $log->info(
      sprintf( "Starting ping health check on %s..",
        $current_master->get_hostinfo() )
    );
    # 执行函数  wait_until_unreachable() 是个while(1)的循环
    ( $ret, $ssh_reachable ) = $_master_ping->wait_until_unreachable();
    if ( $ret eq '2' ) {
      $log->error(
"Target master's advisory lock is already held by someone. Please check whether you monitor the same master from multiple monitoring processes."
      );
      croak;
    }
    elsif ( $ret ne '0' ) {
      croak;
    }
    $log->warning(
      sprintf( "Master %s is not reachable!", $current_master->get_hostinfo() )
    );
    if ($ssh_reachable) {
      $log->warning("SSH is reachable.");
    }
    else {
      $log->warning("SSH is NOT reachable.");
    }
    $func_rc = 0;
  };
  # 检查 eval 代码块有有没有异常
  if ($@) {
    $log->error("Error happened on health checking. $@");
    undef $@;
    return $func_rc;
  }
  # 更新状态标识文件
  $_status_handler->update_status($MHA::ManagerConst::ST_PING_FAILED_S);
  # 返回以下内容
  return ( $func_rc, $current_master, $ssh_reachable );
}

sub wait_until_master_is_dead {
  my $exit_code = 1;
  my ( $ret, $dead_master, $ssh_reachable ) =
    wait_until_master_is_unreachable();
  if ( !defined($ret) || $ret ne '0' ) {
    $log->error("Error happened on monitoring servers.");
    return $exit_code;
  }

  if ($g_check_only) {
    return 0;
  }

  # this should not happen
  unless ($dead_master) {
    $log->error("Dead master not found!\n");
    return $exit_code;
  }

  # Master fails!
  # Reading config file and connecting to all hosts except master again
  # to check current availability
  $exit_code = eval {
    $log->info( "Connecting to a master server failed. Reading configuration "
        . "file $g_global_config_file and $g_config_file again, and trying to connect to all servers to "
        . "check server status.." );
    my $conf = new MHA::Config(
      logger     => $log,
      globalfile => $g_global_config_file,
      file       => $g_config_file
    );

    my ( $sc_ref, $binlog_server_ref ) = $conf->read_config();
    my @servers_config = @$sc_ref;
    $_server_manager = new MHA::ServerManager( servers => \@servers_config );
    $_server_manager->set_logger($log);
    $log->debug(
      sprintf( "Skipping connecting to dead master %s.",
        $dead_master->get_hostinfo() )
    );
    $_server_manager->connect_all_and_read_server_status(
      $dead_master->{hostname},
      $dead_master->{ip}, $dead_master->{port} );
    my @dead_servers  = $_server_manager->get_dead_servers();
    my @alive_servers = $_server_manager->get_alive_servers();
    $log->info("Dead Servers:");
    $_server_manager->print_dead_servers();
    $log->info("Alive Servers:");
    $_server_manager->print_alive_servers();
    $log->info("Alive Slaves:");
    $_server_manager->print_alive_slaves();
    $_server_manager->print_failed_slaves_if();
    $_server_manager->print_unmanaged_slaves_if();

    my $real_master = $_server_manager->get_orig_master();
    if ( $dead_master->{id} ne $real_master->{id} ) {
      $log->error(
        sprintf(
"Monitor detected %s failed, but actual master server is %s. Check replication configurations again.",
          $dead_master->get_hostinfo(),
          $real_master->get_hostinfo()
        )
      );
      return 1;
    }

    # When this condition is met, master is actually alive.
    if ( $_server_manager->get_alive_server_by_id( $dead_master->{id} ) ) {
      $log->warning("master is actually alive. starting monitoring again.");
      return $RETRY;
    }
    if (
      $_server_manager->validate_slaves(
        $servers_config[0]->{check_repl_filter}
      )
      )
    {
      $log->error( "At least one alive slave is not correctly configured. "
          . "Can't execute failover" );
      return 1;
    }

    $log->info("Master is down!");
    $log->info("Terminating monitoring script.");
    $_server_manager->disconnect_all() if ($_server_manager);
    return $MHA::ManagerConst::MASTER_DEAD_RC;
  };
  if ($@) {
    $log->warning("Got Error: $@");
    undef $@;
    $exit_code = 1;
  }
  return 1 if ( !defined($exit_code) );
  return $MHA::ManagerConst::MASTER_DEAD_RC, $dead_master, $ssh_reachable
    if ( $exit_code == $MHA::ManagerConst::MASTER_DEAD_RC );
  return $exit_code;
}

sub prepare_for_retry {
  eval {
    $_status_handler->update_status($MHA::ManagerConst::ST_RETRYING_MONITOR_S);
    $log->info("Waiting for $g_wait_on_monitor_error seconds for retrying..");
    sleep $g_wait_on_monitor_error;
    MHA::NodeUtil::drop_file_if( $_status_handler->{status_file} );
  };
  if ($@) {
    MHA::ManagerUtil::print_error(
      "Got Error on prepare_for_retry at monitor: $@", $log );
    undef $@;
  }
}

sub finalize_on_error {
  eval {

    # Monitor failure happened
    $_status_handler->update_status($MHA::ManagerConst::ST_CONFIG_ERROR_S)
      if ($_status_handler);
    if ( $g_wait_on_monitor_error > 0 ) {
      $log->info(
        "Waiting for $g_wait_on_monitor_error seconds for error exit..");
      sleep $g_wait_on_monitor_error;
    }
    MHA::NodeUtil::drop_file_if( $_status_handler->{status_file} )
      if ($_status_handler);
  };
  if ($@) {
    MHA::ManagerUtil::print_error(
      "Got Error on finalize_on_error at monitor: $@", $log );
    undef $@;
  }
}

sub finalize {
  eval {
    MHA::NodeUtil::drop_file_if( $_status_handler->{status_file} )
      if ($_status_handler);
  };
  if ($@) {
    MHA::ManagerUtil::print_error( "Got Error on finalize at monitor: $@",
      $log );
    undef $@;
  }

}

sub main {
  local $SIG{INT} = $SIG{HUP} = $SIG{QUIT} = $SIG{TERM} = \&exit_by_signal;
  local @ARGV = @_;
  GetOptions(
    'global_conf=s'           => \$g_global_config_file,
    'conf=s'                  => \$g_config_file,
    'check_only'              => \$g_check_only,
    'check_repl_health'       => \$g_check_repl_health,
    'seconds_behind_master=i' => \$g_seconds_behind_master,
    'monitor_only'            => \$g_monitor_only,
    'interactive=i'           => \$g_interactive,
    'wait_on_monitor_error=i' => \$g_wait_on_monitor_error,
    'workdir=s'               => \$g_workdir,
    'manager_workdir=s'       => \$g_workdir,
    'log_output=s'            => \$g_logfile,
    'manager_log=s'           => \$g_logfile,
    'skip_ssh_check'          => \$g_skip_ssh_check,          # for testing
    'skip_check_ssh'          => \$g_skip_ssh_check,
    'ignore_fail_on_start'    => \$g_ignore_fail_on_start,
  );
  setpgrp( 0, $$ ) unless ($g_interactive);

  unless ($g_config_file) {
    print "--conf=<server config file> must be set.\n";
    return 1;
  }

  while (1) {
    my ( $exit_code, $dead_master, $ssh_reachable ) =
      wait_until_master_is_dead();
    my $msg = sprintf( "Got exit code %d (%s).",
      $exit_code,
      $exit_code == $MHA::ManagerConst::MASTER_DEAD_RC
      ? "Master dead"
      : "Not master dead" );
    $log->info($msg) if ($log);
    if ($g_check_only) {
      finalize();
      return $exit_code;
    }
    if ( $exit_code && $exit_code == $RETRY ) {
      prepare_for_retry();
    }
    else {
      if ( $exit_code && $exit_code != $MHA::ManagerConst::MASTER_DEAD_RC ) {
        finalize_on_error();
      }
      elsif ($g_monitor_only) {
        finalize();
      }
      return ( $exit_code, $dead_master, $ssh_reachable );
    }
  }
}

1;
