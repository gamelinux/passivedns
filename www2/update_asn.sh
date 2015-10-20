#!/bin/bash

php get_ipaddress.php |/bin/nc6 whois.cymru.com 43 |php update_ip.php 
