#!/bin/bash

# Este script está basado en el benchmark CIS CentOS Linux 7 v2.1.0
# Enlace: https://benchmarks.cisecurity.org/tools2/linux/CIS_CentOS_Linux_7_Benchmark_v2.1.0.pdf

# Funcion para comprobar que un sistema de archivos este deshabilitado
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
}

main

