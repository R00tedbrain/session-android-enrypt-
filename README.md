![SESION](https://github.com/user-attachments/assets/8e809f2b-e16d-435d-928e-695b7b99f8d5)


If want contribute for develop new fork, at time i doned a one layer more encryptiom, we must finish thread-scoop encryption for any chat to add the 2on layer

if want contribute or any quetion here is my session ID, for the moment i will be busy in other projects but i will try to fnish threadscop for any chat ID , private

session ID: 0512735a4650ffaae7203dfaeff8439f4e88688cd1d4e2218884f1ec9b4eed7a7a




Changelogs VS normal session:


Changelog: Increase Key Seed Size from 128 to 256 Bits

·Key Generation: Updated KeyPairUtilities to generate a 256-bit (32-byte) random seed instead of the previous 128-bit (16-byte) seed.
·Backward Compatibility: Added logic to detect old 128-bit seeds and pad them to 256 bits, ensuring restored accounts still function properly.
·Mnemonic Support: Preserved existing mnemonic derivation code, which naturally supports 25-word phrases for 256-bit seeds (versus 13 words for 128-bit). No UI changes required.
·Storage & Persistence: Verified that IdentityKeyUtil and shared preferences logic remain compatible with the longer seeds (now 64 hex characters).
·Logging & Debugging: Introduced additional log statements in key generation, storage, and onboarding flows to assist with troubleshooting.


Added commonlib : Module of https://github.com/R00tedbrain/Encrypt-Decrypt-AndroidAPK

Added universal encrpyt layer "Extrasecurityactivity" On menu Settings , and on Chat windows menu,
·This add a layer that encrypt with AES256 gcm / Xchacha20  before encrypt with session protocol,  
Steps : plain text > ExtraSecurityEncryption>sesion protocol = reciber = sesion protocoldecrypt>ExtrasecurityDecrypt>plaintext
·In settings can manage Key, import and share keys via QR


Next Features working :
·ADD another layer encryption "Thread-Scoop" can change it with threadid any diferent key for any chat ( Getting dificults if any one want contribuye my session ID is published contact)

·In-band Signature Verification
Currently, the sender’s public key is embedded in the message payload along with the signature. This could allow an attacker to substitute the key, reducing verification to a simple integrity check. The improvement is to securely obtain and use a pre-validated public key for signature verification.

·Using Public Keys as AES-GCM Keys
The system currently uses the recipient's X25519 public key directly as the AES-GCM symmetric key for onion routing, which could let anyone with the public key decrypt messages. The improvement is to replace this with proper asymmetric encryption (e.g., using crypto_box_seal) so that only the intended recipient can decrypt the message.

this week be avalible for download, the problem the only can comunicate with the same version/fork of session normal sesion version cant contact with new fork
