JWT Sign Tool

```
# (1) RSA 개인키 생성 (2048비트)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key_plain.pem

# (2) self-signed 인증서 생성 (유효기간 825일 예시)
openssl req -x509 -new -key key_plain.pem -sha256 -days 825 -subj "/CN=test-jwt-cert" -out cert.pem

# (3) 개인키를 PKCS#8 형식으로 강력하게 암호화
#    PBES2 + AES-256-CBC, PBKDF2(HMAC-SHA256), 반복 600000회
openssl pkcs8 -topk8 -in key_plain.pem -out key_encrypted.pem -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 600000

# (4) 평문 개인키는 반드시 폐기
shred -u key_plain.pem   # (선택) 안전 삭제

```
