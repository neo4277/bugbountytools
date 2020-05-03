#!/bin/bash

set -m

#
# For future, use input/args to dig for CNAME and check for host there.
# Or host and look there..
# OR grep OrgName in whois if IP...
#

if [ $# -gt 0 ]; then
        domain=$1
else
        echo Enter domain name:
        read domain
fi

if [[ "$domain" == *".amazonaws."* ]]; then
	echo Amazon AWS detected...
	http -b GET http://$domain | grep -E -q '<Code>NoSuchBucket</Code>|<li>Code: NoSuchBucket</li>' && echo "Subdomain takeover may be possible" || echo "Subdomain takeover is not possible"
fi

if [[ "$domain" == *".github."* ]]; then
	Github Pages detected... 
	http -b GET http://$domain | grep -F -q "<strong>There isn't a GitHub Pages site here.</strong>" && echo "Subdomain takeover may be possible" || echo "Subdomain takeover is not possible"
fi

if [[ "$domain" == *".herokudns.com" ]]; then
	Heroku detected... 
	http -b GET http://$domain | grep -F -q "//www.herokucdn.com/error-pages/no-such-app.html" && echo "Subdomain takeover may be possible" || echo "Subdomain takeover is not possible"
fi

if [[ "$domain" == *".readme.io" ]]; then
	Readme.io detected... 
	http -b GET http://$domain | grep -F -q "Project doesnt exist... yet!" && echo "Subdomain takeover may be possible" || echo "Subdomain takeover is not possible"
fi
