#!/bin/sh
# Download the large test hives (MIT, Eric Zimmerman's Registry test set)
# at a pinned commit into tests/fixtures/ez-large/, checking each SHA-256.
set -eu
cd "$(dirname "$0")/fixtures"
mkdir -p ez-large
base=https://raw.githubusercontent.com/EricZimmerman/Registry/1b0b3c414569debb5ffcc629de28e3ff27145a42/Registry.Test/Hives
while read -r sum name; do
    path="ez-large/$name"
    if [ ! -f "$path" ]; then
        curl -sfL -o "$path" "$base/$(printf %s "$name" | sed "s/ /%20/g")"
    fi
    echo "$sum  $path" | shasum -a 256 -c --quiet -
done <<EOF
b171ea9638c71c7b3cc9595e19378d63bb8251917e5d6296bdd92c0c4324eb28  DRIVERS
dc43388d50ecfadd85053e2345f62324c2b0b2901a6945d480a2899f0e8c5185  ERZ_Win81_UsrClass.dat
aff9ffc0922a33810e74404be5371acf2325a8ef8260c0b05ddeb744af114fa0  NTUSER slack.DAT
8d5fdee75d69b878a0bf602f7a15f0410c5622b9c8c84a5c2f346d44a8cdb759  NTUSER.DAT
658c4323cc2c4e33e09ef3e5251651300ff1a49937e136242565cc5c49fd5e96  SOFTWARE
ec01a4ec205c5354a4ad1d5d088f45e2331ffb13773dcc7008e6ea6f2175466f  SYSTEM
6dbfecef68d01ddaedaec98b9142e3c17ae9d4a6ec98456680f0c9a74a054a07  UsrClass 1.dat
e82d3cca1c33eb6efa322fb88df8a17d2f5fb072cd2baea0ecb87fce559886fb  UsrClass BEEF000E.dat
e59f1fb3d437b544627c57bf58427762e32e9f8e3f330a3c1c8179f727448efa  UsrClass FTP.dat
7ff60b93c7f0640907ccb943105a10da64398c957bb23d3b87da5dc22c7df315  UsrClass zip files unicode.dat
232a03165b46650f1c0705d917e50eb867fe3db1a342d032e68cd5ea1d2f0870  UsrClass-win7.dat
8b30584fea3e51c037069f16d518b42c0196c02a76ec3056a045fe3b1642da50  UsrClassJVM.dat
EOF
