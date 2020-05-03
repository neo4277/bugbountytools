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
folder=/Users/$USER/SubdomainScans/${domain}/${now}/

mkdir -p ${folder}

echo Checking shodan...
shodan domain $domain | sed "s,$(printf '\033')\\[[0-9;]*[a-zA-Z],,g" > "${folder}""shodan ${time}"

echo Shodan CNAME only...
echo "${folder}""shodan ${time}" | grep CNAME > echo "${folder}""shodan CNAME only ${time}"

echo Checking sublist3r...
python /Users/$USER/Sublist3r/sublist3r.py -d $domain -n -o "${folder}""sublist3r ${time}" > /dev/null

echo Starting to get CNAMES for items in Sublist3r...
for file in "${folder}sublist3r ${time}"; do
	while read -r line; do
		dig "$line" >> "${folder}sublist3r DiG Records ${time}"
	done < "$file"
done
echo "$(<"${folder}sublist3r DiG Records ${time}")" | grep CNAME > "${folder}""sublist3r with CNAME ${time}"

#http -b GET http://{SOURCE DOMAIN NAME} | grep -E -q '<Code>NoSuchBucket</Code>|<li>Code: NoSuchBucket</li>' && echo "Subdomain takeover may be possible" || echo "Subdomain takeover is not possible"

echo Done!
