#!/bin/bash

# Este script está basado en el benchmark CIS CentOS Linux 7 v2.1.0
# Enlace: https://benchmarks.cisecurity.org/tools2/linux/CIS_CentOS_Linux_7_Benchmark_v2.1.0.pdf

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
}

# Ejecucion de la funcion main
main
