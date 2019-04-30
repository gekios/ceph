# mgr_plugin_dashboard_smoke.sh
#
# smoke test the MGR dashboard module and check its SUSE branding
#
# args: None
#
# Credit where credit is due: Ricardo Dias wrote the more complicated curl
# commands :-)

set -ex

URL=$(ceph mgr services 2>/dev/null | jq .dashboard | sed -e 's/"//g')
if [ ! -n "$URL" ]; then
  echo "ERROR: dashboard is not available"
  false
fi

# check the login screen
curl --insecure --silent $URL 2>&1 > dashboard.html
test -s dashboard.html
file dashboard.html | grep "HTML document"
# verify SUSE branding (in title and suse_favicon)
grep -i "suse" dashboard.html
echo "Login screen OK" >/dev/null

# set a password for the admin user
ceph dashboard ac-user-set-password admin admin >/dev/null

# get JWT token
TOKEN=$(curl --insecure -s -H "Content-Type: application/json" -X POST \
            -d '{"username":"admin","password":"admin"}'  $API_URL/api/auth \
            | jq -r .token)

# pass the login screen
result=$(curl --insecure -s -H "Authorization: Bearer $TOKEN " \
               -H "Content-Type: application/json" -X GET \
               ${URL})


# script continues beyond this line - check result, issue more curl commands,
# validate other screens ... (?)
