# JWKS_Server_AES_Encryption
This is the third part of the JWKS project series in my Foundations of Cybersecurity class. The requirements for this project were to include AES encryption for securing private keys stored in the database. The AES encryption will ensure that the private keys are protected while being stored and are only accessible to the server when decrypted securely. I used the Python cryptography library to read the encryption key from an environment variable. 

To run this project, you will need to have Python 3, flask, pyjwt, request, and cryptography installed along with unittest and coverage, and SQLite. From there, you have to copy the repository and create and activate a virtual machine. I used venv for this project. The server will still run on port 8080 and you can still interact with the server using curl. 

The features in this code include:
- AES encryption of private keys
- Environment variable encryption keys
- Secure storage
- Key management
- JWKS server functionality

To run this project:
- You will need Python 3.x, flask, pyjwt, requests, cryptography, unittest, coverage and SQLite
- Clone the repository
- Set up a virtual environment
- Install all dependencies (flask, pyjwt, requests and cryptography
- Run the server using python app.py

To run the tests:
- Use python -m unittest test_jwt.py
- Then install the coverage package
- Then run the tests using coverage
- Type coverage run -m unittest test_jwt.py
- Type coverage report -m
