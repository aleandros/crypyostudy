#!/bin/bash

command="$1"
# Create a fake dummy CA then sign a new certificate using that CA.
# The commands are intended to be executed in the same order as the "case" branches.
# For exmaple:
# 1) ./create_cer.sh generate_key
# 2) ./create_cer.sh generate_csr
# 3) ./create_cer.sh view_csr
# And so on

case "$command" in
    generate_key)
        # This generates the private key which of course, should not be shared
        # with anyone, not even the certificate authority
        openssl genpkey -algorithm RSA -out output/domain_key.pem -pkeyopt rsa_keygen_bits:2048
        ;;
    generate_csr)
        # Create Certificate Signing Request for the CA
        openssl req -new -key output/domain_key.pem -out output/domain_request.csr
        ;;
    view_csr)
        # Show csr fields in human readable formula
        openssl req -in output/domain_request.csr -text
        ;;
    sign_certificate)
        # Since the signkey is the one issued by ourselves, this makes it
        # a self-signed certificate. Valid for 30 days.
        openssl x509 -req \
            -days 30 \
            -in output/domain_request.csr \
            -signkey output/domain_key.pem \
            -out output/domain_cert.crt
        ;;
    view_crt)
        openssl x509 -in output/domain_cert.crt -text
        ;;
    generate_localhost_key)
        # The excercise used EC:P-256 but it doesn't seem to work on my Mac's
        # openssl implementation right now.
        # It would require to change the algorithm to EC and set the
        # pkeyopt options to ec_paramgen_curve:P-256
        openssl genpkey \
            -algorithm RSA \
            -out output/localhost_key.pem \
            -pkeyopt rsa_keygen_bits:2048
        ;;
    generate_localhost_csr)
        openssl req \
            -new \
            -key output/localhost_key.pem \
            -out output/localhost_request.csr
        ;;
    sign_localhost_csr)
        openssl x509 -req \
            -days 365 \
            -in output/localhost_request.csr \
            -CAkey output/domain_key.pem \
            -CA output/domain_cert.crt \
            -out output/localhost_cert.crt \
            -set_serial 123456789 \
            -extfile v3.ext
        ;;
    server)
        # More issues with openssl mac that I don't feel like
        # debugging right now
        openssl s_server -accept 8888 -www \
            -cert output/localhost_cert.crt \
            -key output/localhost_key.pem \
            # -cert_chain output/domain_cert.crt \
            # -build_chain
        ;;
    *)
        echo "Wrong command" 1>&2
        exit 1
        ;;
esac
