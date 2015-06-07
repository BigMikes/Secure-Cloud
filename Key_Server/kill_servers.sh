#!/bin/bash

process_name="key_server"

#show pid of the processes 
ps axf | grep $process_name | grep -v grep | awk '{print "kill -9 " $1}' | sh
