#!/bin/bash
clear
systemctl status bind9
systemctl status postfix
systemctl status dovecot
systemctl status apache2
