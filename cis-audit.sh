#!/bin/bash

# Este script está basado en el benchmark CIS CentOS Linux 7 v2.1.0
# Enlace: https://benchmarks.cisecurity.org/tools2/linux/CIS_CentOS_Linux_7_Benchmark_v2.1.0.pdf

function ensure_packet_redirect_is_disable {
  if [[ "$(sysctl net.ipv4.conf.all.send_redirects)" == "net.ipv4.conf.all.send_redirects = 0" ]] &&\
    [[ "$(sysctl net.ipv4.conf.default.send_redirects)" == "net.ipv4.conf.default.send_redirects = 0" ]]; then
    return 0
  fi
  return 1
}

function ensure_ip_forwarding_disable {
  if [[ "$(sysctl net.ipv4.ip_forward)" == "net.ipv4.ip_forward = 0" ]]; then
    return 0
  fi
  return 1
}

function ensure_port_not_listening {
  netstat -an | grep LIST | grep ":25[[:space:]]"
}

function ensure_service_is_disabled {
  if [[ "$(systemctl is-enabled "${1}")" == "disabled" ]]; then
    return 0
  fi
  return 1
}

function ensure_ntp_restrict {
  grep "^restrict" /etc/ntp.conf | \
    grep "restrict -4 default kod nomodify notrap nopeer noquery" &&\
    grep "^server" /etc/ntp.conf
}

function ensure_ntp_installed {
  rpm -q ntp | grep "ntp*"
  return $?
}

function ensure_filesystem_integrity {
  crontab -u root -l | grep aide
  grep -r aide /etc/cron.* /etc/crontab
}

function ensure_is_installed {
  rpm -q "${1}" | grep ${1}"*"
  return $?
}

function check_gpg_global_is_active {
  grep ^gpgcheck /etc/yum.conf
}

function ensure_gpg_keys {
  rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'
}

function check_repositories {
  yum repolist
}

function check_autofs_disabled {
  local IS_AUTOFS_ENABLED=0
  local result="$(systemctl is-enabled autofs)"

  if [[ "${result}" == "disabled" ]]; then
    return "${IS_AUTOFS_ENABLED}"
  else
    return 1
  fi
}

function check_permision_on_external_partition {
  mount | grep "${2}" | grep "${1}"
}

function check_sticky_bit {
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
}

# Funcion para comprobar si una particion existe
# y si tiene cierto permiso
function check_permision_on_partition {
  mount | grep "${2}" | grep "${1}"
}

# Funcion para comprobar si una particion existe
function check_partition {
  mount | grep "${1}"
}

# Funcion para comprobar que un sistema de archivos esta deshabilitado
function filesystem_is_disabled {
  local filesystem="${1}"
  local E_FILE_SYSTEM_DIABLED=0

  local result_modprobe="$(modprobe -n -v "${filesystem}")"
  local result_lsmod="$(lsmod | grep "${filesystem}")"

  if [[ "${result_modprobe}" == "install /bin/true" ]] && [[ -z "${result_lsmod}" ]]; then
    return "${E_FILE_SYSTEM_DIABLED}"
  else
    return 1
  fi
}

# Funcion que envuelve a otras funciones para
function function_wrapper {
# comprobar si su resultado es correcto o no.
  func_name=$1
  shift
  args=$@
  ${func_name} ${args}
  if [[ "$?" -eq 0 ]]; then
    echo ${func_name} ${args} OK
  else
    echo ${func_name} ${args} ERROR
  fi
}

# Funcion principal que realiza la llamada a las funciones
# que comprueban las auditorias del benchmark
function main {
  # FILESYSTEM
  # CIS 1.1.1.1
  function_wrapper filesystem_is_disabled cramfs

  # CIS 1.1.1.2
  function_wrapper filesystem_is_disabled freevxfs

  # CIS 1.1.1.3
  function_wrapper filesystem_is_disabled jffs2

  # CIS 1.1.1.4
  function_wrapper filesystem_is_disabled hfs

  # CIS 1.1.1.5
  function_wrapper filesystem_is_disabled hfsplus

  # CIS 1.1.1.6
  function_wrapper filesystem_is_disabled squashfs

  # CIS 1.1.1.7
  function_wrapper filesystem_is_disabled udf

  # CIS 1.1.1.8 # May Remove
  function_wrapper filesystem_is_disabled vfat

  # CIS 1.1.2
  function_wrapper check_partition /tmp

  # CIS 1.1.3
  function_wrapper check_permision_on_partition nodev /tmp

  # CIS 1.1.4
  function_wrapper check_permision_on_partition nosuid /tmp

  # CIS 1.1.5
  function_wrapper check_permision_on_partition noexec /tmp

  # CIS 1.1.6
  function_wrapper check_partition /var

  # CIS 1.1.7
  function_wrapper check_partition /var/tmp

  # CIS 1.1.8
  function_wrapper check_permision_on_partition nodev /var/tmp

  # CIS 1.1.9
  function_wrapper check_permision_on_partition nosuid /var/tmp

  # CIS 1.1.10
  function_wrapper check_permision_on_partition noexec /var/tmp

  # CIS 1.1.11
  function_wrapper check_partition /var/log

  # CIS 1.1.12
  function_wrapper check_partition /var/log/audit

  # CIS 1.1.13
  function_wrapper check_partition /home

  # CIS 1.1.14
  function_wrapper check_permision_on_partition nodev /home

  # CIS 1.1.15
  function_wrapper check_permision_on_partition nodev /dev/shm

  # CIS 1.1.16
  function_wrapper check_permision_on_partition nosuid /dev/shm

  # CIS 1.1.17
  function_wrapper check_permision_on_partition noexec /dev/shm

  # CIS 1.1.[18-20]
  function_wrapper check_permision_on_external_partition nodev
  function_wrapper check_permision_on_external_partition nosuid
  function_wrapper check_permision_on_external_partition noexec

  # CIS 1.1.21
  function_wrapper check_sticky_bit

  # CIS 1.1.22 # May Remove
  function_wrapper check_autofs_disabled

  # CIS 1.2.1
  function_wrapper check_repositories

  # CIS 1.2.2
  function_wrapper ensure_gpg_keys

  # CIS 1.2.3
  function_wrapper check_gpg_global_is_active

  # CIS 1.3.1
  function_wrapper ensure_is_installed aide

  # CIS 1.3.2
  function_wrapper ensure_filesystem_integrity

  # SERVICES
  # CIS 2.2.1.1
  function_wrapper ensure_is_installed ntp

  # CIS 2.2.1.2
  function_wrapper ensure_ntp_restrict

  # CIS 2.2.3
  function_wrapper ensure_service_is_disabled avahi-daemon

  # CIS 2.2.4
  function_wrapper ensure_service_is_disabled cups

  # CIS 2.2.5
  function_wrapper ensure_service_is_disabled dhcpd

  # CIS 2.2.6
  function_wrapper ensure_service_is_disabled slapd

  # CIS 2.2.7
  function_wrapper ensure_service_is_disabled nfs

  # CIS 2.2.8
  function_wrapper ensure_service_is_disabled named

  # CIS 2.2.9
  function_wrapper ensure_service_is_disabled vsftpd

  # CIS 2.2.10
  function_wrapper ensure_service_is_disabled httpd

  # CIS 2.2.11
  function_wrapper ensure_service_is_disabled dovecot

  # CIS 2.2.12
  function_wrapper ensure_service_is_disabled smb

  # CIS 2.2.13
  function_wrapper ensure_service_is_disabled squid

  # CIS 2.2.14
  function_wrapper ensure_service_is_disabled snmpd

  # CIS 2.2.16
  function_wrapper ensure_service_is_disabled ypserv

  # CIS 2.2.17
  function_wrapper ensure_service_is_disabled rsh.socket
  function_wrapper ensure_service_is_disabled rlogin.socket
  function_wrapper ensure_service_is_disabled rexec.socket

  # CIS 2.2.18
  function_wrapper ensure_service_is_disabled telnet.socket

  # CIS 2.2.19
  function_wrapper ensure_service_is_disabled tftp.socket

  # CIS 2.2.20
  function_wrapper ensure_service_is_disabled rsyncd

  # CIS 2.2.21
  function_wrapper ensure_service_is_disabled ntalk

  # NETWORK CONFIGURATION
  # CIS 3.1.1
  function_wrapper ensure_ip_forwarding_disable

  # CIS 3.1.2
  function_wrapper ensure_packet_redirect_is_disable

  # CIS 3.6.1
  function_wrapper ensure_is_installed iptables
}

# Ejecucion de la funcion main
main

