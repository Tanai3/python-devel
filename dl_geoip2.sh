#!/bin/sh

wget geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
gunzip -v GeoLite2-City.mmdb.gz
