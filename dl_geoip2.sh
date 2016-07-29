#!/bin/sh

wget geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
mkdir -v GeoIP
mv -v GeoLite2-City.mmdb.gz ./GeoIP
gunzip -v GeoIP/GeoLite2-City.mmdb.gz
