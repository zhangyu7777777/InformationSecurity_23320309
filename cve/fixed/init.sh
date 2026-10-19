#!/bin/bash

while ! curl -s -m 5 "http://${COUCHDB_AUTH}@${COUCHDB_URL}/" >/dev/null; do
    sleep 1
done

curl -s -X PUT "http://${COUCHDB_AUTH}@${COUCHDB_URL}/_users"
curl -s -X PUT "http://${COUCHDB_AUTH}@${COUCHDB_URL}/_replicator"
curl -s -X PUT "http://${COUCHDB_AUTH}@${COUCHDB_URL}/_global_changes"
