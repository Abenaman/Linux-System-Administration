#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ] ; then
    echo 'Domain or/and tld is not specified !!!'
    exit 1
fi
GEN_LOC="/etc/ssl/cagen"

#
# Create openssl.cnf with placeholders
#
echo "Prepare data..."
rm -rf $GEN_LOC
mkdir $GEN_LOC
cat <<EOF >$GEN_LOC/openssl.cnf
#
# OpenSSL example configuration file.
# This is mostly being used for generation of certificate requests.
#

# This definition stops the following lines choking if HOME isn't
# defined.
HOME			= .
RANDFILE		= \$ENV::HOME/.rnd

# Extra OBJECT IDENTIFIER info:
#oid_file		= \$ENV::HOME/.oid
oid_section		= new_oids

# To use this configuration file with the "-extfile" option of the
# "openssl x509" utility, name here the section containing the
# X.509v3 extensions to use:
# extensions		= 
# (Alternatively, use a configuration file that has only
# X.509v3 extensions in its main [= default] section.)

[ new_oids ]

# We can add new OIDs in here for use by 'ca', 'req' and 'ts'.
# Add a simple OID like this:
# testoid1=1.2.3.4
# Or use config file substitution like this:
# testoid2=\${testoid1}.5.6

# Policies used by the TSA examples.
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

####################################################################
[ ca ]
default_ca	= CA_default		# The default ca section

####################################################################
[ CA_default ]

dir		= /etc/ssl/cagen	# Where everything is kept
certs		= \$dir/certs		# Where the issued certs are kept
crl_dir		= \$dir/crl		# Where the issued crl are kept
database	= \$dir/index.txt	# database index file.
unique_subject	= no			# Set to 'no' to allow creation of
					# several certs with same subject.
new_certs_dir	= \$dir/newcerts		# default place for new certs.

certificate	= \$dir/cacert.pem 	# The CA certificate
serial		= \$dir/serial 		# The current serial number
crlnumber	= \$dir/crlnumber	# the current crl number
					# must be commented out to leave a V1 CRL
crl		= \$dir/crl.pem 		# The current CRL
private_key	= \$dir/private/cakey.pem # The private key
RANDFILE	= \$dir/private/.rand	# private random number file

x509_extensions	= usr_cert		# The extensions to add to the cert

# Comment out the following two lines for the "traditional"
# (and highly broken) format.
name_opt 	= ca_default		# Subject Name options
cert_opt 	= ca_default		# Certificate field options

# Extension copying option: use with caution.
# copy_extensions = copy

# Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
# so this is commented out by default to leave a V1 CRL.
# crlnumber must also be commented out to leave a V1 CRL.
# crl_extensions	= crl_ext

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= sha512		# use public key default MD
preserve	= no			# keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy		= policy_match

# For the CA policy
[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

# For the 'anything' policy
# At this point in time, you must list all acceptable 'object'
# types.
[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

####################################################################
[ req ]
default_bits		= 4096 
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions	= v3_ca	# The extensions to add to the self signed cert

# Passwords for private keys if not present they will be prompted for
# input_password = secret
# output_password = secret

# This sets a mask for permitted string types. There are several options. 
# default: PrintableString, T61String, BMPString.
# pkix	 : PrintableString, BMPString (PKIX recommendation before 2004)
# utf8only: only UTF8Strings (PKIX recommendation after 2004).
# nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
# MASK:XXXX a literal mask value.
# WARNING: ancient versions of Netscape crash on BMPStrings or UTF8Strings.
string_mask = utf8only

# req_extensions = v3_req # The extensions to add to a certificate request

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= EE
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Tartumaa

localityName			= Locality Name (eg, city)
localityName_default		= Tartu

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= System Administration course

# we can do this but it is not needed normally :-)
#1.organizationName		= Second Organization Name (eg, company)
#1.organizationName_default	= World Wide Web Pty Ltd

organizationalUnitName		= Organizational Unit Name (eg, section)
#organizationalUnitName_default	= Institute of Computer Science

commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64

# SET-ex3			= SET extension number 3

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20

unstructuredName		= An optional company name

[ usr_cert ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
subjectAltName=@alternate_names

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This is required for TSA certificates.
# extendedKeyUsage = critical,timeStamping

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]


# Extensions for a typical CA


# PKIX recommendation.

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer

basicConstraints = critical,CA:true

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# keyUsage = cRLSign, keyCertSign

# Some might want this also
# nsCertType = sslCA, emailCA

# Include email address in subject alt name: another PKIX recommendation
# subjectAltName=email:copy
# Copy issuer details
# issuerAltName=issuer:copy

# DER hex encoding of an extension: beware experts only!
# obj=DER:02:03
# Where 'obj' is a standard or added object
# You can even override a supported extension:
# basicConstraints= critical, DER:30:03:01:01:FF

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always

[ proxy_cert_ext ]
# These extensions should be added when creating a proxy certificate

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This really needs to be in place for it to be a proxy certificate.
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

####################################################################
[ tsa ]

default_tsa = tsa_config1	# the default TSA section

[ tsa_config1 ]

# These are used by the TSA reply generation only.
dir		= ./demoCA		# TSA root directory
serial		= \$dir/tsaserial	# The current serial number (mandatory)
crypto_device	= builtin		# OpenSSL engine to use for signing
signer_cert	= \$dir/tsacert.pem 	# The TSA signing certificate
					# (optional)
certs		= \$dir/cacert.pem	# Certificate chain to include in reply
					# (optional)
signer_key	= \$dir/private/tsakey.pem # The TSA private key (optional)
signer_digest  = sha256			# Signing digest to use. (Optional)
default_policy	= tsa_policy1		# Policy if request did not specify it
					# (optional)
other_policies	= tsa_policy2, tsa_policy3	# acceptable policies (optional)
digests     = sha1, sha256, sha384, sha512  # Acceptable message digests (mandatory)
accuracy	= secs:1, millisecs:500, microsecs:100	# (optional)
clock_precision_digits  = 0	# number of digits after dot. (optional)
ordering		= yes	# Is ordering defined for timestamps?
				# (optional, default: no)
tsa_name		= yes	# Must the TSA name be included in the reply?
				# (optional, default: no)
ess_cert_id_chain	= no	# Must the ESS cert id chain be included?
				# (optional, default: no)

[ alternate_names ]
EOF
echo "DNS.0=*."$1"."$2 >> $GEN_LOC/openssl.cnf
echo "DNS.1="$1"."$2 >> $GEN_LOC/openssl.cnf
echo "DNS.2=mail."$1"."$2 >> $GEN_LOC/openssl.cnf

#
# Prepare required folders and files 
#
mkdir $GEN_LOC/certs $GEN_LOC/crl $GEN_LOC/newcerts $GEN_LOC/private
echo 02 > $GEN_LOC/serial
touch $GEN_LOC/index.txt.attr
touch $GEN_LOC/index.txt

#
# Generate CA certs (passphrase=securepass)
#
echo "Generate CA..."
openssl req -new -x509 -days 360 -keyout $GEN_LOC/private/cakey.pem -out $GEN_LOC/cacert.pem -config $GEN_LOC/openssl.cnf -passout pass:securepass -subj "/C=EE/ST=Tartumaa/L=Tartu/O=System Administration course/OU=./CN="$2"/emailAddress=root@"$1"."$2

#
# Generate cert for our host
#
echo "Generate and sign certs for host..."
openssl genrsa -out $GEN_LOC/newkey.pem 4096
openssl req -new -key $GEN_LOC/newkey.pem -out $GEN_LOC/newreq.pem -days 360 -config $GEN_LOC/openssl.cnf -passout pass:'' -subj "/C=EE/ST=Tartumaa/L=Tartu/O=System Administration course/OU=./CN="$1"."$2"/emailAddress=root@"$1"."$2
openssl ca -batch -config $GEN_LOC/openssl.cnf -passin pass:securepass -policy policy_anything -out $GEN_LOC/newcert.pem -infiles $GEN_LOC/newreq.pem

#
# Distribute certs
#
echo "Distributing certificates..."
cp $GEN_LOC/newcert.pem /etc/ssl/certs/server.crt
cp $GEN_LOC/cacert.pem /etc/ssl/certs/cacert.crt
cp $GEN_LOC/newkey.pem /etc/ssl/private/server.key
chgrp ssl-cert /etc/ssl/private/server.key
chmod g+r /etc/ssl/private/server.key
chmod a+r /etc/ssl/certs/server.crt
chmod a+r /etc/ssl/certs/cacert.crt

echo "Distributing next cloud certificates (could fail if never started)..."
cp /etc/ssl/certs/server.crt /var/snap/nextcloud/current/certs/live/server.pem
cp /etc/ssl/private/server.key /var/snap/nextcloud/current/certs/live/server.key
cp /etc/ssl/certs/cacert.crt /var/snap/nextcloud/current/certs/live/cacert.pem

echo "Calling update..."
update-ca-certificates --fresh

#
# Adjust configuration for services
#
echo "Adjusting TLS configuration in services..."
# Postfix
grep -q '^[# ]*smtpd_tls_security_level *=' /etc/postfix/main.cf && sed -i '/^[ #]*smtpd_tls_security_level[ ]*=/c\smtpd_tls_security_level=may' /etc/postfix/main.cf || echo 'smtpd_tls_security_level=may' >> /etc/postfix/main.cf
grep -q '^[# ]*smtpd_tls_key_file *=' /etc/postfix/main.cf && sed -i '/^[ #]*smtpd_tls_key_file[ ]*=/c\smtpd_tls_key_file=/etc/ssl/private/server.key' /etc/postfix/main.cf || echo 'smtpd_tls_key_file=/etc/ssl/private/server.key' >> /etc/postfix/main.cf
grep -q '^[# ]*smtpd_tls_cert_file *=' /etc/postfix/main.cf && sed -i '/^[ #]*smtpd_tls_cert_file[ ]*=/c\smtpd_tls_cert_file=/etc/ssl/certs/server.crt' /etc/postfix/main.cf || echo 'smtpd_tls_cert_file=/etc/ssl/certs/server.crt' >> /etc/postfix/main.cf
grep -q '^[# ]*smtpd_use_tls *=' /etc/postfix/main.cf && sed -i '/^[ #]*smtpd_use_tls[ ]*=/c\smtpd_use_tls=yes' /etc/postfix/main.cf || echo 'smtpd_use_tls=yes' >> /etc/postfix/main.cf
grep -q '^[# ]*smtpd_tls_loglevel *=' /etc/postfix/main.cf && sed -i '/^[ #]*smtpd_tls_loglevel[ ]*=/c\smtpd_tls_loglevel=1' /etc/postfix/main.cf || echo 'smtpd_tls_loglevel=1' >> /etc/postfix/main.cf
grep -q '^[# ]*smtp_tls_loglevel *=' /etc/postfix/main.cf && sed -i '/^[ #]*smtp_tls_loglevel[ ]*=/c\smtp_tls_loglevel=1' /etc/postfix/main.cf || echo 'smtp_tls_loglevel=1' >> /etc/postfix/main.cf

# Dovecot
grep -q '^[# ]*ssl *=' /etc/dovecot/conf.d/10-ssl.conf && sed -i '/^[ #]*ssl[ ]*=/c\ssl=yes' /etc/dovecot/conf.d/10-ssl.conf || echo 'ssl=yes' >> /etc/dovecot/conf.d/10-ssl.conf
grep -q '^[# ]*ssl_cert *=' /etc/dovecot/conf.d/10-ssl.conf && sed -i '/^[ #]*ssl_cert[ ]*=/c\ssl_cert=</etc/ssl/certs/server.crt' /etc/dovecot/conf.d/10-ssl.conf || echo 'ssl_cert=</etc/ssl/certs/server.crt' >> /etc/dovecot/conf.d/10-ssl.conf 
grep -q '^[# ]*ssl_key *=' /etc/dovecot/conf.d/10-ssl.conf && sed -i '/^[ #]*ssl_key[ ]*=/c\ssl_key=</etc/ssl/private/server.key' /etc/dovecot/conf.d/10-ssl.conf || echo 'ssl_key=</etc/ssl/private/server.key' >> /etc/dovecot/conf.d/10-ssl.conf 

# Apache
grep -q '^[# ]*SSLCertificateFile' /etc/apache2/apache2.conf && sed -i '/^[ #]*SSLCertificateFile/c\SSLCertificateFile /etc/ssl/certs/server.crt' /etc/apache2/apache2.conf || echo 'SSLCertificateFile /etc/ssl/certs/server.crt' >> /etc/apache2/apache2.conf
grep -q '^[# ]*SSLCertificateKeyFile' /etc/apache2/apache2.conf && sed -i '/^[ #]*SSLCertificateKeyFile/c\SSLCertificateKeyFile /etc/ssl/private/server.key' /etc/apache2/apache2.conf || echo 'SSLCertificateKeyFile /etc/ssl/private/server.key' >> /etc/apache2/apache2.conf
grep -q '^[# ]*SSLCACertificateFile' /etc/apache2/apache2.conf && sed -i '/^[ #]*SSLCACertificateFile/c\SSLCACertificateFile /etc/ssl/certs/cacert.crt' /etc/apache2/apache2.conf || echo 'SSLCACertificateFile /etc/ssl/certs/cacert.crt' >> /etc/apache2/apache2.conf

# Roundcube
grep -q '^[#$ ]*config.*default_host' /etc/roundcube/config.inc.php && sed -i '/^[ #$]*config.*default_host/c\\x24config\x5B\x27default_host\x27\x5D=\x27tls://'$1'\x2E'$2'\x27;' /etc/roundcube/config.inc.php || echo 'SSLCACertificateFile=/etc/ssl/certs/cacert.crt' >> /etc/roundcube/config.inc.php

#
# Restart services
#
echo "Restarting services..."
systemctl restart postfix
systemctl restart dovecot
systemctl restart apache2
service snapd restart
snap disable nextcloud
snap enable nextcloud

echo "Done"