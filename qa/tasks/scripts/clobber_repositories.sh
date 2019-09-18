# clobber_repositories.sh
#
# args: some repositories in format name:url
#

set -ex

if [ -d /etc/zypp/repos.d.bck ] ; then
    echo "Repos were already clobbered. Doing nothing." 2>/dev/null
    exit 0
fi

echo "Repos BEFORE clobber" 2>/dev/null
zypper lr -upEP

cp -a /etc/zypp/repos.d /etc/zypp/repos.d.bck
rm -f /etc/zypp/repos.d/*

for repo_spec in "$@" ; do
	repo_url=${repo_spec#*:}
	repo_name=${repo_spec%%:*}
    if [[ "$repo_spec" =~ '!' ]] ; then
	repo_prio=${repo_name#*\!}
	repo_name=${repo_name%\!*}
        zypper \
            --non-interactive \
            addrepo \
            --priority $repo_prio \
            --refresh \
            --no-gpgcheck \
            $repo_url \
            $repo_name
    else
        zypper \
            --non-interactive \
            addrepo \
            --refresh \
            --no-gpgcheck \
            $repo_url \
            $repo_name
    fi
done

zypper --non-interactive --no-gpg-checks refresh

echo "Repos AFTER clobber" 2>/dev/null
zypper lr -upEP
