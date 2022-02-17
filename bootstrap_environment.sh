#!/usr/bin/env sh
#
# Microprobe support scripts
#

set -e
scriptpath=$( cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P )

ver="$1"
if [ -z "$ver" ]; then
    ver=3
fi

python="$(command -v "python$ver" || echo "python$ver not found in path")"
if [ ! -x "$python" ]; then
    echo "$python"
    exit 1
fi

if [ -L "$python" ]; then
    name=$(basename "$(readlink "$python")")
else
    name=$(basename "$python")
fi

rm -fr "$scriptpath/venv"
rm -fr "$scriptpath/venv-$name"

virtualenv "$scriptpath/venv-$name" --prompt="(Microprobe $name) " --python="$(command -v "python$ver")"
ln -s "$scriptpath/venv-$name" "$scriptpath/venv"
# shellcheck disable=SC1090
. "$scriptpath/venv-$name/bin/activate"
pip3 install -U pip
pip3 install -U -r requirements_devel.txt
pip3 install -U -r requirements.txt
# shellcheck disable=SC2046
pip3 install -U $(pip3 list | grep "\." | cut -d " " -f 1)
# shellcheck disable=SC2046
pip3 install -U $(pip3 list | grep "\." | cut -d " " -f 1)
# shellcheck disable=SC2046
pip3 install -U $(pip3 list | grep "\." | cut -d " " -f 1)

{

    echo "export PATH=\$PATH:$(find "$(pwd)/targets" -type d -name tools -exec echo -n {}: \;)"
    echo "export PYTHONPATH=$scriptpath/src:\$PYTHONPATH"
    echo "export MICROPROBEDATA=$scriptpath/targets/"
    echo "export MICROPROBETEMPLATES=$(find "$(pwd)/targets" -type d -name templates -exec echo -n {}: \;)"
    echo "export MICROPROBEWRAPPERS=$(find "$(pwd)/targets" -type d -name wrappers -exec echo -n {}: \;)"
    echo "echo Microprobe environment activated"

} >> "$scriptpath/venv-$name/bin/activate"
