import jwt
from ecdsa import SigningKey
import json

signing_key = SigningKey.generate()
signing_pem = signing_key.to_pem()
verifying_key = signing_key.get_verifying_key()
verifying_pem = verifying_key.to_pem()

payload = {"some": "example"}
signed_token = jwt.encode(payload, signing_pem, algorithm='ES256')
extracted_payload = jwt.decode(signed_token, verifying_pem)

assert(payload == extracted_payload)

print "\nPayload:\n%s\n" % json.dumps(payload)
print "Signed token:\n%s\n" % signed_token
print "Extracted payload:\n%s\n" % json.dumps(extracted_payload)
