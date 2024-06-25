#!/bin/bash
set -e

new_dir() {
	if [ ! -d "$1" ]; then
		mkdir $1
	fi
}

new_dir "./logs"
new_dir "./res"
new_dir "./db"
new_dir "./fidb"
new_dir "./ghidra_projects"

