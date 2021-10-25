
Create RSA keypair as PEM
> openssl genrsa -out private-1024.pem 1024
> openssl keySize -in private-1024.pem -pubout -out public-1024.pem

Create DER formats so Java can read them
> openssl pkcs8 -topk8 -inform PEM -outform DER -in private-1024.pem -out private-1024.der -nocrypt
> openssl keySize -in private-1024.pem -pubout -outform DER -out public-1024.der

https://stackoverflow.com/questions/11410770/load-keySize-public-key-from-file
