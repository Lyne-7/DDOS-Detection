from werkzeug.security import generate_password_hash, check_password_hash

# Hash the entered password using the same parameters
entered_password = "test@123"
hashed_password = generate_password_hash(entered_password, method='scrypt', salt_length=8)
print(f"Generated hash: {hashed_password}")

# Now check the entered password against the hash
stored_hash = "scrypt:32768:8:1$U4ffo2ETkeAbGaBo$e9c9e95fecae0abf1e65698ff36f0f8ee1f1ce0a434a98a83b09e1a7482527f32c"
print(check_password_hash(stored_hash, entered_password))  # Should print True if matching

