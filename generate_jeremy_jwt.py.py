
import jwt
import datetime

# The secret obtained from the .env file
NEXTAUTH_SECRET = "82a464f1c3509a81d5c973c31a23c61a"

# User information to embed in the token for 'jeremy'
payload = {
    "name": "jeremy",  # Authenticating as jeremy
    "email": "jeremy@example.com", # Placeholder email
    "sub": "2", # Subject identifier, changed from 1 to 2 for a new user
    "iat": datetime.datetime.utcnow(),
    "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7) # Token expires in 7 days
}

# Generate the JWT token
encoded_jwt = jwt.encode(payload, NEXTAUTH_SECRET, algorithm="HS256")

print(encoded_jwt)

