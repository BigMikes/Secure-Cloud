#!/bin/bash

base_folder="./"
cert_folder="Certs/"
cert_ext=".pem"
files_pub="fileserver_public"
keys_priv="keyserver_privkey"
process_name="key_server"

#run key servers
for i in {2..5..1}
do
	./$process_name 127.0.0.1 5555 $i $base_folder$cert_folder$files_pub$cert_ext $base_folder$cert_folder$keys_priv$i$cert_ext &

	sleep 3
done



