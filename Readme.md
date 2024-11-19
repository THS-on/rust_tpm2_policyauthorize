# Rust example for using policyauthorize

Use `gen_key.sh` to setup the key to signing key for the policy and the example PCR policy.

## Setting up swtpm

```
mkdir /tmp/tpmdir

swtpm_setup --tpm2 \
    --tpmstate /tmp/tpmdir \
    --createek --decryption --create-ek-cert \
    --create-platform-cert \
    --pcr-banks sha1,sha256 \
    --display

modprobe tpm_vtpm_proxy
swtpm chardev --vtpm-proxy  --tpmstate dir=/tmp/tpmdir --tpm2
```