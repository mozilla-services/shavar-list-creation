#!/usr/bin/env bash

_usage() {
  cat <<EOF
usage: ${0} [run]

arguments:
  run    main entrypoint, execute shavar list creation scripts and exit

EOF
}

if [[ "${#}" -gt 0 ]]; then
  CMD=${1} && shift

  case "${CMD}" in
    run)
      python lists2safebrowsing.py
      python lists2webkit.py
      ;;

    *)
      echo "ERROR: unknown command: \"${CMD}\""
      _usage && exit 1
      ;;
  esac

else
  _usage && exit
fi
