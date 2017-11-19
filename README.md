# cryptor.php
## PHP class for encryption and decryption with open_ssl

Because open_ssl cannot work with large text, a function is created to split text (in the background) in sperate chuncks. 
These chuncks are encrypted and decrypted seperately and glued together in the end. 
Works without mcrypt.

Encryption is done with open_ssl AES-256-CBC method.

Generates a random IV with openssl_random_pseudo_bytes for each message and is prefixed to the encrypted_text.
Generates a random nonce (number used once) with openssl_random_pseudo_bytes used as salt for each message. 
The purpose of random IV and nonce: When the same message is encrypted twice, the encrypted_txt is always different.

## Instruction (standard secretkey is provided as private static property):

$encrypted_txt    = Cryptor::doEncrypt($plain_txt);

$plain_txt        = Cryptor::doDecrypt($encrypted_txt);

## Or:

$encrypted_txt    = Cryptor::doEncrypt($plain_txt, 'secretkey');

$plain_txt        = Cryptor::doDecrypt($encrypted_txt, 'secretkey');
