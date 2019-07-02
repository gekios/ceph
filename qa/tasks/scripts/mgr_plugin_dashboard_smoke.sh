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


function test_screen(){
test -s $1.html
file $1.html | grep "HTML document"
# verify SUSE branding (in title and suse_favicon)
grep -i "suse" $1.html
echo "$1 screen OK" >/dev/null
}

# check the login screen
curl --insecure --silent $URL 2>&1 > dashboard.html
test_screen dashboard

# set a password for the admin user
ceph dashboard ac-user-set-password admin admin >/dev/null

# get JWT token
TOKEN=$(curl --insecure -s -H "Content-Type: application/json" -X POST \
            -d '{"username":"admin","password":"admin"}'  $API_URL/api/auth \
            | jq -r .token)

# pass the login screen
curl --insecure -s -H "Authorization: Bearer $TOKEN " \
               -H "Content-Type: application/json" -X GET \
               ${URL} 2>&1 > main.html
test_screen main

#Check the pools page
curl --insecure -s -H "Authorization: Bearer $TOKEN " \
               -H "Content-Type: application/json" -X GET \
               ${URL}/\#/pool 2>&1 > pools.html
test_screen pools	


#check if the SUSE branded html login and 'About' files exist on the mgr node
test -f /usr/share/ceph/mgr/dashboard/frontend/src/app/core/auth/login/login.component.brand.html
echo "SUSE Branded HTML file OK" >/dev/null
test -f /usr/share/ceph/mgr/dashboard/frontend/src/app/core/navigation/about/about.component.brand.html
echo "SUSE Branded 'About' file OK" >/dev/null

#Check if the SUSE logos exist on the mgr node
declare -a arr=("suse_brand_bright.png" "suse_favicon.png" \
                "suse_logo_footer.png" "suse_logo_login.png" \
                "suse_logo_login.svg" "suse_logo.png" "suse_logo.svg")
for i in "${arr[@]}"
do
        test -f /usr/share/ceph/mgr/dashboard/frontend/src/assets/$i
        echo "$i file OK" >/dev/null
done




