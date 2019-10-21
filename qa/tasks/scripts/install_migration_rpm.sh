#!/bin/bash
# takes two arguments: the full URL and name of the RPM containing the migration ISO
set -ex

function zypper_install {
    local package="$1"
    zypper --non-interactive --no-gpg-checks install \
        --force --no-recommends $package
}

NAME=$1
RPM=$1
if [[ -n $2 ]];
	then
		URL=$2
		type wget
		wget "$URL"
		RPM="${NAME}*.rpm"
		test $RPM
		number_of_rpms=$(ls -1 $RPM | wc --lines)
		test "$number_of_rpms" = "1"
		echo "only one RPM downloaded: good" >/dev/null
		RPM="$(echo $RPM)"
		test -f "$RPM"
		file "$RPM" | grep RPM
fi

zypper_install $RPM
zypper_install suse-migration-sle15-activation

SLE_MIGRATION_YML="/etc/sle-migration-service.yml"
cat <<EOM > $SLE_MIGRATION_YML
use_zypper_migration: false
soft_reboot: false
EOM

cat $SLE_MIGRATION_YML
exit 0
