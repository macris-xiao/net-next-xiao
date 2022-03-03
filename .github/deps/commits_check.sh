#! /bin/bash

set -e

if [ -z "$1" ]; then
    echo "Please specify commit count."
    exit 1
fi

exp_ccount=1
exp_scount=0
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

    for i in 1 2; do
        set +e
        make -s -j"$(nproc)" EXTRA_CFLAGS+="-Werror -Wmaybe-uninitialized" \
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

    echo "----------- Checkpatch ---------------"
    ./scripts/checkpatch.pl --strict -g $commit --ignore FILE_PATH_CHANGES

    echo
    echo "----------- Doc string check ---------"
    # This gets all .c/.h files touched by the commit
    set +e
    files=$(git show --name-only --oneline --no-merges $commit | grep -E '(*\.h|*\.c)')
    ERROR="$?"
    # Grep will exit with 0 if a match is found, 1 if no match is found,
    # and 2 if an error is encountered. 0 and 1 are non-error states for
    # this script, so treat them accordingly
    [ "$ERROR" == 0 -o "$ERROR" == 1 ] || exit "$ERROR"
    set -e

    if [ "$ERROR" == 1 ]; then
        echo " No C files found, skipping...."
    else
        echo $files
        # Run doc string checker on the files in the commit
        ./scripts/kernel-doc -Werror -none $files
    fi

    echo
    echo "----------- Reverse xmas tree check ------------"
    PATCH_FILE=$(git format-patch -1 $commit)
    ./xmastree.py "$PATCH_FILE"
    rm "$PATCH_FILE"

    echo
    echo "----------- Smatch check ------------"

    # This gets all .c files touched by the commit
    # N.B. This is not safe in the case where filenames include newlines
    readarray -t files < <( git show --name-only --oneline --no-merges $commit | grep '\.c$')

    for file in "${files[@]}"; do
        echo
        echo "----------- Check ($file) ---------"

        # If the change touches nfp_net_debugfs.c but CONFIG_NFP_DEBUG is not
        # set in the configuration file smatch will exit with an error as there
        # is no rule to build nfp_net_debugfs.o
        if [[ "$file" == "drivers/net/ethernet/netronome/nfp/nfp_net_debugfs.c" ]]; then
            if ! grep -q "CONFIG_NFP_DEBUG=y" .config; then
                echo "Skip as CONFIG_NFP_DEBUG not set in .config"
                continue
            fi
        fi

        set +e
        ./smatch/smatch_scripts/kchecker --spammy "$file" >& .smatch.log
        ERROR="$?"
        set -e
        if [ "$ERROR" -ne 0 ]; then
            cat .smatch.log
            exit "$ERROR"
        fi

        smatch_count=$(grep "\(warning:\|warn:\|error:\)" .smatch.log | wc -l)

        case $file in
        drivers/net/ethernet/netronome/nfp/abm/ctrl.c) ;&
        drivers/net/ethernet/netronome/nfp/abm/qdisc.c) ;&
        drivers/net/ethernet/netronome/nfp/ccm_mbox.c) ;&
        drivers/net/ethernet/netronome/nfp/crypto/tls.c) ;&
        drivers/net/ethernet/netronome/nfp/nfp_net_common.c) ;&
        drivers/net/ethernet/netronome/nfp/nfp_net_sriov.c) ;&
        drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c)
                exp_smatch_count=1 ;;
        drivers/net/ethernet/netronome/nfp/bpf/jit.c) ;&
        drivers/net/ethernet/netronome/nfp/flower/offload.c)
                exp_smatch_count=2 ;;
        drivers/net/ethernet/netronome/nfp/devlink_param.c) ;&
        drivers/net/ethernet/netronome/nfp/nfp_main.c)
                exp_smatch_count=3 ;;
        *)
                exp_smatch_count=0 ;;
        esac

        if [ "$smatch_count" != "$exp_smatch_count" ]; then
            echo "new smatch found! (expected:$exp_smatch_count got:$smatch_count)"
            cat .smatch.log
            exit 1
        fi
    done

    echo
    echo "----------- Sparse check -------------"

    set +e
    make -j"$(nproc)" M="$module" C=2 CF=-D__CHECK_ENDIAN__ >& .sparse.log
    ERROR="$?"
    set -e
    if [ "$ERROR" != "0" ]; then
        cat .sparse.log
        exit "$ERROR"
    fi

    scount=$(grep "\(arning:\|rror:\)" .sparse.log | wc -l)
    if [ $scount -gt $exp_scount ]; then
        echo "new sparse found! (expected:$exp_scount got:$scount)"
        cat .sparse.log
        exit 1
    fi
    echo "Done"

    echo
    echo "----------- Cocci check --------------"
    rm -f .cocci.log
    [ ! -e ./cocci-debug.log ] || rm ./cocci-debug.log
    set +e
    make -j"$(nproc)" M="$module" coccicheck --quiet MODE=report \
        DEBUG_FILE=cocci-debug.log >& .cocci.log
    ERROR="$?"
    set -e
    if [ "$ERROR" -ne 0 ]; then
        cat .cocci.log
        if [ -e cocci-debug.log ]; then
            echo "--- debug file ---"
            cat cocci-debug.log
        fi
        exit "$ERROR"
    fi
    ccount=$(cat .cocci.log | grep "on line" | wc -l)
    if [ $ccount -gt $exp_ccount ]; then
        echo "new coccinelle found!"
        grep "on line" .cocci.log
        if [ -e cocci-debug.log ]; then
            echo "--- debug file ---"
            cat cocci-debug.log
        fi
        exit 1
    fi
    echo "Done"

    echo "========================================================"
    echo
    echo

done
set +e
