#!/bin/bash
export TPM2TOOLS_TCTI="device:/dev/tpmrm1"

mkdir -p data

pushd data
if [ ! -f signing_key_private.pem ]
then 
    openssl ecparam -name secp384r1  -genkey -noout -out signing_key_private.pem
    openssl ec -in signing_key_private.pem -out signing_key_public.pem -pubout
fi

rm -f session.ctx
rm -f signing_key.ctx
rm -f signing_key.name


tpm2_loadexternal -G ecc384 -C o -u signing_key_public.pem -c signing_key.ctx -n signing_key.name

tpm2_startauthsession -S session.ctx
tpm2_policyauthorize -S session.ctx -L authorized.policy -n signing_key.name
tpm2_flushcontext session.ctx

rm -f session.ctx

echo "PCR policy"
tpm2_startauthsession -S session.ctx
tpm2_policypcr -S session.ctx -l sha256:7 -L pcr.policy_desired
tpm2_flushcontext session.ctx

rm -f session.ctx

openssl dgst -sha256 -sign signing_key_private.pem -out pcr.signature pcr.policy_desired

popd