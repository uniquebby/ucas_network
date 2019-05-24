#!/bin/bash


dd if=/dev/urandom bs=2MB count=1 | base64 > client-input.dat
