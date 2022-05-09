#! /bin/bash

set -e

commit_status_init() {
    COMMIT_STATUS_FAIL=0
}

commit_status_set_fail() {
    local reason=$1
    echo "Failed: $reason"
    COMMIT_STATUS_FAIL=1
}

commit_status_get() {
    echo $COMMIT_STATUS_FAIL
}

if [ -z "$1" ]; then
    echo "Please specify commit count."
    exit 1
fi

readonly ncommits=$1

exp_ccount=1
exp_scount=0
module=drivers/net/ethernet/netronome/nfp

# If a commit message contains a Fixes tag or mentions a different commit the
# strict mode of checkpatch.pl will check the tree to make sure that commit
# exits, as our worktree is shallow this check will fail.
#
# To prevent checkpatch.pl from failing transform the shallow worktree to a full
# tree if a commit in the range will trigger this checkpatch.pl check.
#
# NOTE: This is an expensive operation and should only be trigger if needed.
for commit in $(git log --oneline --no-color -$ncommits --reverse | cut -d ' ' -f 1); do
    commit_message=$(git log --oneline -1 $commit | cut -d ' ' -f 2)
    if [ "${commit_message}" == "github-patches-check:" ]; then
        continue
    fi

    if grep -qiP "^fixes:|\bcommit\s+[0-9a-f]{6,40}\b" <<< $(git log -1 --pretty=%B $commit); then
        echo "Check of commit(s) will requier access to the full git tree, fetch the full tree"
        git fetch --quiet --unshallow
        break
    fi
done

for commit in $(git log --oneline --no-color -$ncommits --reverse | cut -d ' ' -f 1); do
    echo "============== Checking $commit ========================"
    commit_status_init

    git checkout $commit

    commit_message=$(git log --oneline -1 | cut -d ' ' -f 2)
    if [ "${commit_message}" == "github-patches-check:" ]; then
        echo " Self-check detected, skipping...."
        continue
    fi

    echo "----------- Compile commit ------------"
    if ! make -s -j"$(nproc)" M="$module" >& .build.log; then
        cat .build.log
        exit 1
    fi

    echo "----------- Checkpatch ---------------"
    if ! ./scripts/checkpatch.pl --strict -g $commit --ignore FILE_PATH_CHANGES; then
        commit_status_set_fail "checkpatch.pl exited with non-zero return code"
    fi

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
        if ! ./scripts/kernel-doc -Werror -none $files; then
            commit_status_set_fail "kernel-doc exited with non-zero return code"
        fi
    fi

    echo
    echo "----------- Reverse xmas tree check ------------"
    PATCH_FILE=$(git format-patch -1 $commit)
    if ! ./xmastree.py "$PATCH_FILE"; then
        commit_status_set_fail "xmastree.py exited with non-zero return code"
    fi
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

        if ! ./smatch/smatch_scripts/kchecker --spammy "$file" >& .smatch.log; then
            commit_status_set_fail "kchekcer for $file exited with non-zero return code"
            cat .smatch.log
        else
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
                commit_status_set_fail "new smatch found! (expected:$exp_smatch_count got:$smatch_count)"
                cat .smatch.log
            fi
        fi
    done

    echo
    echo "----------- Sparse check -------------"

    if ! make -j"$(nproc)" M="$module" C=2 CF=-D__CHECK_ENDIAN__ >& .sparse.log; then
        commit_status_set_fail "Sparse exited with non-zero return code"
        cat .sparse.log
    else
        scount=$(grep "\(arning:\|rror:\)" .sparse.log | wc -l)
        if [ $scount -gt $exp_scount ]; then
            commit_status_set_fail "new sparse found! (expected:$exp_scount got:$scount)"
            cat .sparse.log
        fi
    fi
    echo "Done"

    echo
    echo "----------- Cocci check --------------"
    rm -f .cocci.log cocci-debug.log

    if ! make -j"$(nproc)" M="$module" coccicheck --quiet MODE=report DEBUG_FILE=cocci-debug.log >& .cocci.log; then
        commit_status_set_fail "coccicheck exited with non-zero return code"
        cat .cocci.log
        if [ -e cocci-debug.log ]; then
            echo "--- debug file ---"
            cat cocci-debug.log
        fi
    else
        ccount=$(cat .cocci.log | grep "on line" | wc -l)
        if [ $ccount -gt $exp_ccount ]; then
            commit_status_set_fail "new coccinelle found! (expected:$exp_ccount got:$ccount)"
            cat .cocci.log
            if [ -e cocci-debug.log ]; then
                echo "--- debug file ---"
                cat cocci-debug.log
            fi
        fi

        # Check for specific class(es) of coccicheck warnings.
        # TODO: All warnings should be fixed and this step shall fail if any warning
        #       is generated not just for specific patterns.
        if grep -q "WARNING avoid newline at end of message in NL_SET_ERR_MSG_MOD$" .cocci.log; then
            commit_status_set_fail "coccicheck found error class 'newline at end of message in NL_SET_ERR_MSG_MOD'"
            cat .cocci.log
        fi
    fi
    echo "Done"

    # Get the status of all checks and only move to next commit if all passed
    echo
    echo "----------- Checks summary --------------"
    if [[ $(commit_status_get) -eq 0 ]]; then
        echo "All checks passed for $commit"
    else
        echo "One or more checks failed for $commit"
        exit 1
    fi

    echo "========================================================"
    echo
    echo

done
set +e
