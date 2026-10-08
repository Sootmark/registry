#!/bin/sh
# Download the large test hives at pinned commits, checking each SHA-256:
# Eric Zimmerman's Registry test set (MIT) into tests/fixtures/ez-large/;
# plaso's SYSTEM, SOFTWARE-RunTests, NTUSER-WIN7.DAT and NTUSER.DAT (Apache-2.0) into
# tests/fixtures/plaso-large/; and hives of Andrew Rathbun's Windows 10 and
# 11 VMs (MIT, DFIR Artifact Museum; extracted with 7z) into
# tests/fixtures/rathbun-large/: SYSTEM, SOFTWARE and NTUSER.DAT of Windows
# 10, SYSTEM of Windows 11.
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

plaso=https://raw.githubusercontent.com/log2timeline/plaso/ac6da7129f6cf3f43a352b6c4906374cf071533e/test_data
mkdir -p plaso-large
while read -r sum name; do
    path="plaso-large/$name"
    if [ ! -f "$path" ]; then
        curl -sfL -o "$path" "$plaso/$name"
    fi
    echo "$sum  $path" | shasum -a 256 -c --quiet -
done <<EOF
96dc1f1cc3c0b44ef9af72d1c18a8e6a4338c67988f303d05693ca4be6bf7eb9  SYSTEM
6e70645c80b79a97bd7038cc1ca5672d53f228125f2bfa61fc1ea120e10f5036  SOFTWARE-RunTests
672abb15ae62fa8c002c5ee0a730cf83cd5f40706d5ffdec8f1179cf47a0bd03  NTUSER-WIN7.DAT
4a3232850f9677de96774b4de0020ac7f5e2efeb5e4576a200bb751d9e1c9d1d  NTUSER.DAT
EOF

museum=https://raw.githubusercontent.com/AndrewRathbun/DFIRArtifactMuseum/fdcb1fab0c7b00e89129668d9c30174dd4ea3e5b/Windows/Registry
mkdir -p rathbun-large
while read -r archive_sum version hives; do
    dir="rathbun-large/win$version"
    mkdir -p "$dir"
    for hive in $hives; do
        if [ ! -f "$dir/$hive" ]; then
            if [ ! -f "$dir.7z" ]; then
                curl -sfL -o "$dir.7z" "$museum/Win$version/RathbunVM/RathbunVM_W${version}RegistryHives.7z"
                echo "$archive_sum  $dir.7z" | shasum -a 256 -c --quiet -
            fi
            7z e -y -bd -o"$dir" "$dir.7z" "$hive" >/dev/null
        fi
    done
    rm -f "$dir.7z"
done <<EOF
f4f321cf45ae06db0fa832c9103699bdc6114b3017fdb6671fa6bd0971c7a9aa 10 SYSTEM SOFTWARE NTUSER.DAT
23c8d3cf99fd0cdc91da4d6ad7d8c91e03d8fb0b744c6bc70d737f8b2eee268a 11 SYSTEM
EOF
while read -r sum path; do
    echo "$sum  rathbun-large/$path" | shasum -a 256 -c --quiet -
done <<EOF
61293882afec46472a2b8f6c896b4657626461fbbfed67ff100ae06da8e4b680 win10/SYSTEM
cd25478f854dbacd4c044c001e36746fb3e1ea702426aa0e5fa2e8f396615d15 win10/SOFTWARE
523716419e2a661e2a719b63a24c031567bfcf22113b7e86bb35d3604ff942d3 win10/NTUSER.DAT
d65c718c91e50d57fd549e9fa8782a5edad60c8cdcd597bb40481a81854496ee win11/SYSTEM
EOF
