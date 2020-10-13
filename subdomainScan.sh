#!/bin/bash
#set -m

if [ $# -gt 0 ]; then
	domain=$1
else
	echo Enter domain name:
	read domain
fi

now="$(date +"%m-%d-%Y")"
time="$(date +"%l;%M %p")"
folder="/usr/SubdomainScans/${domain}/${now}/"

mkdir -p ${folder}

echo Starting... "(${folder})"

echo Checking shodan...
#shodan domain $domain | sed "s,$(printf '\033')\\[[0-9;]*[a-zA-Z],,g" > "${folder}shodan ${time}"
shodan domain $domain | sed "s,$(printf '\033')\\[[0-9;]*[a-zA-Z],,g" >> "${folder}shodan"

#echo Shodan CNAME only...
#echo "${folder}""shodan ${time}" | grep CNAME > echo "${folder}""shodan CNAME only ${time}"

echo Checking sublist3r...
#python /$USER/Sublist3r/sublist3r.py -d $domain -n -o "${folder}sublist3r ${time}" > /dev/null
python3 /usr/bin/sublist3r.py -d $domain -n -o "${folder}sublist3r" >> /dev/null

echo Starting to get CNAMES for items in Sublist3r...
#for file in "${folder}sublist3r ${time}"; do
sed 's/<BR>/\n/g' "${folder}sublist3r" >> "${folder}sublist3r - Sorted"
for file in "${folder}sublist3rSorted"; do
	while read -r line; do
#		dig "$line" >> "${folder}sublist3r DiG Records ${time}"
		dig "$line" >> "${folder}sublist3r DiG Records"
		status=`curl -o /dev/null -Isw '%{http_code}' "$line" --max-time 5`
		if [ "$status" == 2* ] || [ "$status" == 3* ]; then
#			echo "$line" >> "${folder}Webpages That Are Up"
			echo "$line"
		fi
	done < "$file"
done
#echo "$(<"${folder}sublist3r DiG Records ${time}")" | grep CNAME > "${folder}""sublist3r with CNAME ${time}"
echo "$(<"${folder}sublist3r DiG Records")" | grep CNAME >> "${folder}""sublist3r with CNAME"

echo Processing data...
#echo "$(<"${folder}shodan ${time}")" | grep -e CNAME > "${folder}shodan CNAME spaces"
echo "$(<"${folder}shodan")" | grep -e CNAME >> "${folder}shodan CNAME spaces"
#awk -v RS=" " '{print}' "${folder}sublist3r with CNAME ${time}" > "${folder}sublist3r CNAME spaces"
awk -v RS=" " '{print}' "${folder}sublist3r with CNAME" >> "${folder}""sublist3r CNAME spaces"
awk -v RS="	" '{print}' "${folder}sublist3r CNAME spaces" >> "${folder}""sublist3r CNAME spaces 2"
#awk -v RS=" " '{print}' "${folder}shodan CNAME spaces" > "${folder}shodan CNAME spaces 2"
#awk -v RS="	" '{print}' "${folder}shodan CNAME spaces 2" > "${folder}shodan CNAME spaces 3"
#awk -v RS=" " '{print}' "${folder}sublist3r CNAME spaces" > "${folder}sublist3r CNAME spaces"
#awk -v RS="	" '{print}' "${folder}sublist3r CNAME spaces" > "${folder}sublist3r CNAME spaces"
#echo "$(<"${folder}shodan CNAME spaces 2")" | grep -e amazonaws -e github.io -e herokudns -e readme.io > "${folder}shodan CNAME spaces 3"
#echo "$(<"${folder}shodan CNAME spaces 2")" | grep -e CNAME > "${folder}shodan CNAME spaces 3"

echo Checking scans for possible subdomain takeovers...
echo "$(<"${folder}sublist3r CNAME spaces 2")" | grep -e amazonaws -e github.io -e herokudns -e readme.io -e azurewebsites.net -e cloudapp. -e azure.com -e trafficmanager.net -e .blob.core.windows.net -e cloudfront.net >> "${folder}sublist3r CNAME spaces 3"
#echo "$(<"${folder}sublist3r DiG Records ${time}")" | grep -e amazonaws -e github.io -e herokudns -e readme.io -e azurewebsites.net -e cloudapp. -e azure.com -e trafficmanager.net -e .blob.core.windows.net -e cloudfront.net -e "192\.30\.252\.153$" -e "192\.30\.252\.154$"> "${folder}sublist3r CNAME OneLine"
echo "$(<"${folder}sublist3r DiG Records")" | grep -e amazonaws -e github.io -e herokudns -e readme.io -e azurewebsites.net -e cloudapp. -e azure.com -e trafficmanager.net -e .blob.core.windows.net -e cloudfront.net -e "192\.30\.252\.153$" -e "192\.30\.252\.154$" >> "${folder}""sublist3r CNAME OneLine"
while read -r line
do
	#echo --------------------------
	#echo "$line"
	#echo -------------------------- 
#	echo Detecting Amazon...
#	grep -q 'amazonaws' <<< $line && (http --ignore-stdin -b GET http://$line | grep -E -q '<Code>NoSuchBucket</Code>|<li>Code: NoSuchBucket</li>' && echo "[!!!] $line - Subdomain takeover may be possible for $line" || echo "Takeover is not possible for $line.")
	grep -q 'amazonaws' <<< $line && http --ignore-stdin -F -b GET http://$line | grep -E -q '<Code>NoSuchBucket</Code>|<li>Code: NoSuchBucket</li>' && echo "[!!!] $line - Subdomain takeover may be possible for $line"

#	echo Detecting Github...
#	grep -q 'github.io' <<< $line && (http --ignore-stdin -b GET http://$line | grep -F -q "<strong>There isn't a GitHub Pages site here.</strong>" && echo "[!!!] $line - Subdomain takeover may be possible for $line" || echo "Takeover is not possible for $line.")
	grep -q 'github\.io' <<< $line && http --ignore-stdin -F -b GET http://$line | grep -F -q "<strong>There isn't a GitHub Pages site here.</strong>" && echo "[!!!] $line - Subdomain takeover may be possible for $line"

#	echo Detecting Heroku...
#	grep -q 'herokudns.com' <<< $line && (http --ignore-stdin -b GET http://$line | grep -F -q "//www.herokucdn.com/error-pages/no-such-app.html" && echo "[!!!] $line - Subdomain takeover may be possible for $line" || echo "Takeover is not possible for $line.")
	grep -q 'herokudns\.com' <<< $line && http --ignore-stdin -F -b GET http://$line | grep -F -q "//www.herokucdn.com/error-pages/no-such-app.html" && echo "[!!!] $line - Subdomain takeover may be possible for $line"

#	echo Detecting Readme...
#	grep -q 'readme.io' <<< $line && (http --ignore-stdin -b GET http://$line | grep -F -q "Project doesnt exist... yet!" && echo "[!!!] $line - Subdomain takeover may be possible" || echo "Takeover is not possible for $line.")
	grep -q 'readme.io' <<< $line && http --ignore-stdin -F -b GET http://$line | grep -F -q "Project doesnt exist... yet!" && echo "[!!!] $line - Subdomain takeover may be possible"

	grep -q 'azurewebsites\.net' <<< $line && http --ignore-stdin -F -b GET http://$line | grep -F -q "NXDOMAIN" && echo "[!!!] $line - Subdomain takeover may be possible"
	grep -q 'cloudapp\.' <<< $line && http --ignore-stdin -F -b GET http://$line | grep -F -q "NXDOMAIN" && echo "[!!!] $line - Subdomain takeover may be possible"
	grep -q 'azure\.com' <<< $line && http --ignore-stdin -F -b GET http://$line | grep -F -q "NXDOMAIN" && echo "[!!!] $line - Subdomain takeover may be possible"
	grep -q 'trafficmanager\.net' <<< $line && http --ignore-stdin -F -b GET http://$line | grep -F -q "NXDOMAIN" && echo "[!!!] $line - Subdomain takeover may be possible"
	grep -q '\.blod\.core\.windows\.net' <<< $line && http --ignore-stdin -F -b GET http://$line | grep -F -q "NXDOMAIN" && echo "[!!!] $line - Subdomain takeover may be possible"

#done < "${folder}sublist3r CNAME spaces 3"
#done < "${folder}sublist3r ${time}"
done < "${folder}sublist3r"

while read -r line
do
	grep -q "192\.30\.252\.153" <<< $line && echo "[!!] $line - GitHub IP found."
	grep -q "192\.30\.252\.154" <<< $line && echo "[!!] $line - GitHub IP found."

#done < "${folder}sublist3r DiG Records ${time}"
done < "${folder}sublist3r DiG Records"
tmpfile=$(mktemp)
for file in ${folder}* ; do
#	sort "$file" | uniq -u > /dev/null
#	awk ' !x[$0]++' "$file" > /dev/null
#	awk ' !x[$0]++' "$file" | sponge "$file"
	awk ' !x[$0]++' "$file" > ${tmpfile}
	cat ${tmpfile} > "$file"
	rm -f ${tmpfile}
done
#awk ' !x[$0]++' "${folder}"shodan
#awk ' !x[$0]++' "${folder}"shodan CNAME spaces
#awk ' !x[$0]++' "${folder}"sublist3r
#awk ' !x[$0]++' "${folder}"sublist3r CNAME OneLine
#awk ' !x[$0]++' "${folder}"sublist3r CNAME spaces
#awk ' !x[$0]++' "${folder}"sublist3r CNAME spaces 2
#awk ' !x[$0]++' "${folder}"sublist3r CNAME spaces 3
#awk ' !x[$0]++' "${folder}"sublist3r with CNAME

echo Done!
