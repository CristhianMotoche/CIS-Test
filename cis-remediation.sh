#!/bin/bash

# Este script está basado en el benchmark CIS CentOS Linux 7 v2.1.0
# Enlace: https://benchmarks.cisecurity.org/tools2/linux/CIS_CentOS_Linux_7_Benchmark_v2.1.0.pdf

function disable_autfs {
  systemctl disable autofs
}

function set_sticky_bit {
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
}

# Funcion para emitir un mensaje al usuario sobre la creacion de una particion
function disable_filesystem {
  echo "Deberia crear la siguiente particion: ${1}"
  echo "Puede utiliza LVM para hacerlo"
  echo "HOWTO: http://tldp.org/HOWTO/LVM-HOWTO/"
  echo "Y asignarle los siguientes permisos: ${2}"
}

# Funcion para añadir un sistema de archivos al archivo /etc/modprobe.d/CIS.conf
# para deshabilitarlos
function disable_filesystem {
  local filesystem="${1}"
  local output_file="/etc/modprobe.d/CIS.conf"
  echo "install ${filesystem} /bin/true" >> "${output_file}"
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
# que realizan las recomendaciones del benchmark
function main {
  # CIS 1.1.1.1
  function_wrapper disable_filesystem cramfs

  # CIS 1.1.1.2
  function_wrapper disable_filesystem freevxfs

  # CIS 1.1.1.3
  function_wrapper disable_filesystem jffs2

  # CIS 1.1.1.4
  function_wrapper disable_filesystem hfs

  # CIS 1.1.1.5
  function_wrapper disable_filesystem hfsplus

  # CIS 1.1.1.6
  function_wrapper disable_filesystem squashfs

  # CIS 1.1.1.7
  function_wrapper disable_filesystem udf

  # CIS 1.1.1.8
  function_wrapper disable_filesystem vfat

  # CIS 1.1.[2-5]
  function_wrapper suggest_partition /tmp "(noexec, nodev, nosuid)"

  # CIS 1.1.6
  function_wrapper suggest_partition /var ""

  # CIS 1.1.[7-10]
  function_wrapper suggest_partition /var/tmp "(noexec, nodev, nosuid)"

  # CIS 1.1.11
  function_wrapper suggest_partition /var/log ""

  # CIS 1.1.12
  function_wrapper suggest_partition /var/log/audit ""

  # CIS 1.1.[13-14]
  function_wrapper suggest_partition /home "(nodev)"

  # CIS 1.1.[15-17]
  function_wrapper suggest_partition /dev/shm "(noexec, nodev, nosuid)"

  # CIS 1.1.[18-20]
  function_wrapper suggest_partition "EXTERNAL PARTITIONS" "(noexec, nodev, nosuid)"

  # CIS 1.1.21
  function_wrapper set_sticky_bit

  # CIS 1.1.22
  function_wrapper disable_autfs
}

main

