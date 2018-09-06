#!/usr/bin/env sh
#
# Microprobe support scripts
#

set -e
scriptpath=$( cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P )

python="$(which "python$1" || echo "python$1 not found in path")"
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

virtualenv "$scriptpath/venv-$name" --prompt="(Microprobe $name) " --python="$(which "python$1")"
ln -s "$scriptpath/venv-$name" "$scriptpath/venv"
# shellcheck disable=SC1090
. "$scriptpath/venv-$name/bin/activate"
pip install -r requirements.txt
pip install -r requirements_devel.txt

{

    echo "export PATH=\$PATH:$(find "$(pwd)/targets" -type d -name tools -exec echo -n {}: \;)"
    echo "export PYTHONPATH=$scriptpath/src:\$PYTHONPATH"
    echo "export MICROPROBEDATA=$scriptpath/targets/"
    echo "export MICROPROBETEMPLATES=$(find "$(pwd)/targets" -type d -name templates -exec echo -n {}: \;)"
    echo "export MICROPROBEWRAPPERS=$(find "$(pwd)/targets" -type d -name wrappers -exec echo -n {}: \;)"
    echo "echo Microprobe environment activated"

} >> "$scriptpath/venv-$name/bin/activate"
