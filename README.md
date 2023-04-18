<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>Folder Encryption and Decryption Tool</h1>
    <p>This folder encryption and decryption tool provides an easy way to protect your sensitive files in a directory by encrypting them using AES-GCM and Argon2 for key derivation. The tool works with files in the current directory as well as its subdirectories.</p>

<h2>Features</h2>
<ul>
    <li>Uses AES-GCM for encryption and decryption, providing strong security and authentication.</li>
    <li>Employs the Argon2 key derivation function to derive encryption keys from user-provided passwords, ensuring a robust and secure key generation process.</li>
    <li>Securely deletes original files after encryption and encrypted files after decryption by overwriting the data with random bytes.</li>
    <li>Compatible with Python 3.6 or higher.</li>
    <li>Works with files in the current directory and its subdirectories.</li>
    <li>Graceful handling of errors, including incorrect passwords and missing files.</li>
</ul>

<h2>Security</h2>
<p>The script uses industry-standard cryptography libraries and techniques, making it extremely difficult for an attacker to recover encrypted files without the correct password. AES-GCM ensures that the encrypted data is confidential and tamper-proof, while Argon2 helps protect against brute-force and dictionary attacks on the password.</p>
<p>However, it's important to choose a strong and unique password to maximize the security of your encrypted files. Weak or commonly used passwords can be more easily compromised.</p>

<h2>Requirements</h2>
<p>To run this script, you need Python 3.6 or higher. You'll also need to install the following Python packages using pip:</p>
<pre>
sudo apt install pip
</pip>
<pre>
pip install readchar
pip install cryptography
pip install argon2-cffi
</pre>
<h2>Usage</h2>
<p>To use the script, place lock.py in the directory containing the files you want to encrypt or decrypt and execute the script:</p>
<pre>
python lock.py
</pre>
<p>If there are no encrypted files in the current directory or its subdirectories, the script will prompt you for a password and proceed to encrypt all files. If encrypted files are present, the script will ask for the password to decrypt them.</p>
<p>Remember to keep your password safe, as losing it will make it nearly impossible to recover your encrypted files.</p>
<h2>Disclaimer</h2>
<p>While the script uses strong encryption and key derivation techniques, it's important to understand the risks associated with encryption and securely managing passwords. Always keep backups of your important files and use strong, unique passwords to minimize the risk of data loss or unauthorized access.</p>
<h2>Warning!</h2>
<p>It should go without saying -- DO NOT USE THIS SCRIPT IN YOUR ROOT OR HOME DIRECTORYIES! Using in root will likely brick your system.
</p>
</body>
</html>
