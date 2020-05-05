#!/bin/bash
set -m

if [ $# -gt 0 ]; then
	domain=$1
else
	echo Enter domain name:
	read domain
fi

now="$(date +"%m-%d-%Y")"
time="$(date +"%l;%M %p")"
folder="/Users/$USER/SubdomainScans/${domain}/${now}/"

mkdir -p ${folder}

echo Checking shodan...
shodan domain $domain | sed "s,$(printf '\033')\\[[0-9;]*[a-zA-Z],,g" > "${folder}""shodan ${time}"

#echo Shodan CNAME only...
#echo "${folder}""shodan ${time}" | grep CNAME > echo "${folder}""shodan CNAME only ${time}"

echo Checking sublist3r...
python /Users/$USER/Sublist3r/sublist3r.py -d $domain -n -o "${folder}""sublist3r ${time}" > /dev/null

echo Starting to get CNAMES for items in Sublist3r...
for file in "${folder}sublist3r ${time}"; do
	while read -r line; do
		dig "$line" >> "${folder}sublist3r DiG Records ${time}"
	done < "$file"
done
echo "$(<"${folder}sublist3r DiG Records ${time}")" | grep CNAME > "${folder}""sublist3r with CNAME ${time}"

echo Processing data...
awk -v RS=" " '{print}' "${folder}sublist3r with CNAME ${time}" > "${folder}sublist3r CNAME spaces"
awk -v RS="	" '{print}' "${folder}sublist3r CNAME spaces" > "${folder}sublist3r CNAME spaces 2"
#awk -v RS=" " '{print}' "${folder}sublist3r CNAME spaces" > "${folder}sublist3r CNAME spaces"
#awk -v RS="	" '{print}' "${folder}sublist3r CNAME spaces" > "${folder}sublist3r CNAME spaces"

echo Checking scans for possible subdomain takeovers...
echo "$(<"${folder}sublist3r CNAME spaces 2")" | grep -e amazonaws -e github.io -e herokudns -e readme.io > "${folder}sublist3r CNAME spaces 3"
while read -r line
do
#	echo --------------------------
#	echo "$line"
#	echo --------------------------
	
#	echo Detecting Amazon...
	grep -q 'amazonaws' <<< $line && http --ignore-stdin -b GET http://$line | grep -E -q '<Code>NoSuchBucket</Code>|<li>Code: NoSuchBucket</li>' && echo "[!!!] $line - Subdomain takeover may be possible for $line"

#	echo Detecting Github...
	grep -q 'github.io' <<< $line && http --ignore-stdin -b GET http://$line | grep -F -q "<strong>There isn't a GitHub Pages site here.</strong>" && echo "[!!!] $line - Subdomain takeover may be possible for $line"

#	echo Detecting Heroku...
	grep -q 'herokudns.com' <<< $line && http --ignore-stdin -b GET http://$line | grep -F -q "//www.herokucdn.com/error-pages/no-such-app.html" && echo "[!!!] $line - Subdomain takeover may be possible for $line"

#	echo Detecting Readme...
	grep -q 'readme.io' <<< $line && http --ignore-stdin -b GET http://$line | grep -F -q "Project doesnt exist... yet!" && echo "[!!!] $line - Subdomain takeover may be possible"

echo "------------ $line ------------" >> "${folder}HTTP request results ${time}"
http --ignore-stdin -b GET http://$line >> "${folder}HTTP request results ${time}" 2> /dev/null
echo " " >> "${folder}HTTP request results ${time}"
done < "${folder}sublist3r ${time}"

echo -e "\033[44mDone!"
