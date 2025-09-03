
import jwt
import datetime

# The secret obtained from the .env file
NEXTAUTH_SECRET = "82a464f1c3509a81d5c973c31a23c61a"

# User information to embed in the token
payload = {
    "name": "node",  # Assuming a user named 'node'
    "email": "node@example.com",
    "sub": "1", # Subject identifier
    "iat": datetime.datetime.utcnow(),
    "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7) # Token expires in 7 days
}

# Generate the JWT token
encoded_jwt = jwt.encode(payload, NEXTAUTH_SECRET, algorithm="HS256")

print(encoded_jwt)

