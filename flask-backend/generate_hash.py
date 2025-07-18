import bcrypt

# Replace with your desired password
password = b"admin123"

hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hashed.decode())
