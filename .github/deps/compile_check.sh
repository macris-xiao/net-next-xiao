#! /bin/bash

set -e

if [ -z "$1" ]; then
    echo "Please specify commit count."
    exit 1
fi

readonly ncommits=$1
readonly module=drivers/net/ethernet/netronome/nfp

for commit in $(git log --oneline --no-color -$ncommits --reverse | cut -d ' ' -f 1); do
    echo "============== Checking $commit ========================"
    git checkout $commit

    commit_message=$(git log --oneline -1 | cut -d ' ' -f 2)
    if [ "${commit_message}" == "github-patches-check:" ]; then
        echo " Self-check detected, skipping...."
        continue
    fi

    echo "----------- Compile check ------------"
    make -j"$(nproc)" M="$module" clean

    for i in 1 2; do
        set +e
        make -s -j"$(nproc)" EXTRA_CFLAGS+="-Werror -Wmaybe-uninitialized -Wunused-but-set-variable" \
                M="$module" >& .build.log
        ERROR="$?"
        set -e
        [ "$ERROR" != "0" ] || break
        if [ "$i" != "1" ] || ! grep -q "ERROR: modpost: .* undefined" .build.log; then
            cat .build.log
            exit "$ERROR"
        fi
        # Rebuild entire kernel to refresh symbols
        echo "--------------- Rebuild kernel -----------------"
        make -s -j"$(nproc)"
        echo "-------- Retry compile check ($target) ---------"
    done
done
