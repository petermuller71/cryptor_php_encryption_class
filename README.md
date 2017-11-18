# cryptor.php :: Class for encryption en decryption with open_ssl
PHP class for encryption and decryption of text with open_ssl. 

Because open_ssl cannot work with large text, a function is created to split text (in the background) in sperate chuncks. 
These chuncks are encrypted and decrypted seperately and glued together in the end. 
Works without mcrypt.

Encryption is done with open_ssl AES-256-CBC method.

Instruction:

$encrypted_txt    = Cryptor::doEncrypt($plain_txt);

$plain_txt        = Cryptor::doDecrypt($encrypted_txt);
