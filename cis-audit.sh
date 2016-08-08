#!/bin/bash

# Este script está basado en el benchmark CIS CentOS Linux 7 v2.1.0
# Enlace: https://benchmarks.cisecurity.org/tools2/linux/CIS_CentOS_Linux_7_Benchmark_v2.1.0.pdf

# Funcion para comprobar que un sistema de archivos este deshabilitado
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
}

# Ejecucion de la funcion main
main
