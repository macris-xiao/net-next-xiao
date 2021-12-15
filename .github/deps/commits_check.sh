#! /bin/bash

set -e

if [ -z "$1" ]; then
    echo "Please specify commit count."
    exit 1
fi

exp_ccount=1
module=drivers/net/ethernet/netronome/nfp

for commit in $(git log --oneline --no-color -$1 --reverse | cut -d ' ' -f 1); do
    echo "============== Checking $commit ========================"

    git checkout $commit

    commit_message=$(git log --oneline -1 | cut -d ' ' -f 2)
    if [ "${commit_message}" == "github-patches-check:" ]; then
        echo " Self-check detected, skipping...."
        continue
    fi

    echo "----------- Compile check ------------"
    make -j"$(nproc)" M="$module" clean
    make -j"$(nproc)" EXTRA_CFLAGS+="-Werror -Wmaybe-uninitialized" \
        M="$module" > /dev/null

    echo "----------- Checkpatch ---------------"
    ./scripts/checkpatch.pl --strict -g $commit --ignore FILE_PATH_CHANGES

    # This gets all .c/.h files touched by the commit
    files=$(git show --name-only --oneline --no-merges $commit | grep -E '(*\.h|*\.c)')
    echo
    echo "----------- Doc string check ---------"
    echo $files
    # Run doc string checker on the files in the commit
    ./scripts/kernel-doc -Werror -none $files

    echo
    echo "----------- Reverse xmas tree check ------------"
    PATCH_FILE=$(git format-patch -1 $commit)
    ./xmastree.py "$PATCH_FILE"
    rm "$PATCH_FILE"

    echo
    echo "----------- Sparse check -------------"
    make -j"$(nproc)" M="$module" C=2 CF=-D__CHECK_ENDIAN__ > /dev/null
    echo "Done"

    echo
    echo "----------- Cocci check --------------"
    rm -f .cocci.log
    [ ! -e ./cocci-debug.log ] || rm ./cocci-debug.log
    make -j"$(nproc)" M="$module" coccicheck --quiet MODE=report \
        DEBUG_FILE=cocci-debug.log > .cocci.log
    ccount=$(cat .cocci.log | grep "on line" | wc -l)
    if [ $ccount -gt $exp_ccount ]; then
        echo "new coccinelle found!"
        exit 1
    fi
    echo "Done"

    echo "========================================================"
    echo
    echo

done
set +e
