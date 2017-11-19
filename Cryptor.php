<?php

/************************************************************************************************************************************************
 *
 * Class:  Cryptor
 * 
 * PHP Encryption and decryption class with open_ssl
 * Works also with larger text (because text is split in smaller parts)
 * generates a random IV with openssl_random_pseudo_bytes for each message
 * generates a random nonce (number used once) with openssl_random_pseudo_bytes used as salt for each message 
 * Purpose of random IV and nonce: When the same message is encrypted twice, the encrypted_text is always different
 * IVs and nonces do not have to be kept secret. They are prefixed to the encrypted_text and transmitted in full public view
 * Generates a hash of the encrypted data for integrity check and is prefixed to the encrypted_text
 *
 * Instruction (no secret key provided):
 * encryption:  $encrypted_txt    = Cryptor::doEncrypt($plain_txt);
 * decryption:  $plain_txt        = Cryptor::doDecrypt($encrypted_txt);
 *
 * Instruction (with secret key):
 * encryption:  $encrypted_txt    = Cryptor::doEncrypt($plain_txt, "secret key used for encryption");
 * decryption:  $plain_txt        = Cryptor::doDecrypt($encrypted_txt, "secret key used for encryption");
 *
 * Change class properties (change secret keys, etc)!
 *
 *************************************************************************************************************************************************/


class Cryptor {


    /**
     * Class to encrypt or decrypt a plain_text string with open_ssl
     * open_ssl cannot handle large files. Therefore source is split in smaller parts, and afterwards glued together again
     * generates a random IV with openssl_random_pseudo_bytes for each message
     * generates a random nonce (number used once) with openssl_random_pseudo_bytes used as salt for each message 
     * 
     * IVs and nonces do not have to be kept secret. They are prefixed to the encrypted_text and transmitted in full public view
     * Furthermore: a hash of the encrypted data (for an integrity check) is prefixed to the encrypted_text
     * 
     *
     * @param      string       $plain_txt        Text, to be encrypted
     * @param      string       $encrypted_txt    Text, to be decrypted
     * @param      string       $secretkey        Optional, override with (static private) property 
     * 
     * @property   int          $strspit_nr       Amount of characters to split source (<= 400!), open_ssl cannot encrypt large files
     * @property   string       $rep_letter       Letter used to replace underscore (prevent detecting str_splits)
     * @property   string       $secret_key       Secret_key (sha512 hashvalue is created from this string), used if secret_key is not passed as argument

     * 
     * @return     string       Encrypted or decrypted text
     * 
     * @author     Peter Muller <petermuller71@gmail.com>
     * @version    1.04
     *
     */
    
    static private $strspit_nr = 350;                     // smaller than 400 characters!                    
    static private $rep_letter = 'b';                     // change this (any letter, small or Capital)!
    static private $secret_key = 'This is my secret key'; // change this! (this value is used if secret_key is not passed as argument) 
    
    
    /*
     * doEncrypt
     * Encrypt text
     *
     * @param   string    $plain_txt   Text that will be encrypted
     * @param   string    $secretkey   Optional, override with (static private) property
     * @return  string    Encrypted text
     *
     */
    
    public static function doEncrypt($plain_txt, $secretkey = null) {

       if ($secretkey == null) { $secretkey = self::$secret_key; }    
        
       // add salt to plain_text 
       // salt is actually a nonce (unpredictable random number), so encryption of the same plain_text will leads always to different encrypted_texts  
       // See: http://www.cryptofails.com/post/70059609995/crypto-noobs-1-initialization-vectors
       
       $salt      = substr( base64_encode(openssl_random_pseudo_bytes(16)), 0, 10);    
       $plain_txt = $salt.$plain_txt;
       
       // $plain_text should be split in smaller parts and encrypted seperatly
      
       $arr = str_split($plain_txt, self::$strspit_nr);
       foreach ($arr as $v) { $encrypted_txt .= substr(self::doEncryptDecrypt('encrypt', $secretkey, $v), 0, -2)."_"; }
       
       $encrypted_txt = substr($encrypted_txt, 0, -1);
       
       // smaller parts were glued together with underscore (_) and replaced by a letter 
       
       $encrypted_txt = self::replace("go", $encrypted_txt);
       
       // add hash (for integraty check) to result
       
       $hash  = substr( hash('sha512', $encrypted_txt) , 0, 10);       
       $encrypted_txt = $hash.$encrypted_txt;
       
       return $encrypted_txt; 
    }
 
    
    
    /*
     * doDecrypt
     * Decrypt text
     *
     * @param   string    $encrypted_txt   Text that will be decrypted
     * @param   string    $secretkey       Optional, override with (static private) property
     * @return  string    Decrypted text
     *
     */   
 
   public static function doDecrypt($encrypted_txt, $secretkey = null) {

       if ($secretkey == null) { $secretkey = self::$secret_key; } 

       // get hash, prefixed to encrypted_txt
       
       $hash          = substr($encrypted_txt, 0, 10);
       $encrypted_txt = substr($encrypted_txt, 10);
       
       // check if hash is correct (compare with hash_on_the_fly)
       
       $hash_on_the_fly  = substr( hash('sha512', $encrypted_txt) , 0, 10);
       if ($hash !== $hash_on_the_fly) { return null; }
       
       
       // smaller parts were glued together with underscore (_) and replaced by a letter      
       
       $encrypted_txt   = self::replace("back", $encrypted_txt);

       // encrypted_txt should be split in smaller parts and decrypted seperatly
       
       $arr  = explode("_", $encrypted_txt);
       foreach ($arr as $v) { $decrypted_txt .= self::doEncryptDecrypt('decrypt', $secretkey, $v); }
           
       // remove salt
       $decrypted_txt = substr($decrypted_txt, 10);
       
       return utf8_encode($decrypted_txt);
   }
   
 
   /*
    * doEncryptDecrypt
    * Encrypt or decrypt text 
    *
    * @param   string    $action     Encrypt or decrypt text
    * @param   string    $secretkey  secretkey used for encryption/decryption
    * @param   string    $source     Source that is encrypted or decrypted
    * @return  string
    *
    */
   
    private static function doEncryptDecrypt($action, $secretkey, $source) {
       
        $output     = false;
        
        // hash
        $secretkey  = hash('sha512', $secretkey);
        
        // iv - encrypt method AES-256-CBC expects 16 bytes

        $iv = substr( base64_encode(openssl_random_pseudo_bytes(16)), 0, 16);
        
        if ( $action == 'encrypt' ) 
        {
        
            $output = openssl_encrypt($source, "AES-256-CBC", $secretkey, 0, $iv);
            $output = $iv.base64_encode($output);
        
        } 
        else if( $action == 'decrypt' ) 
        {
            $iv     = substr($source, 0, 16);
            $source = substr($source, 16);
            $output = openssl_decrypt(base64_decode($source), "AES-256-CBC", $secretkey, 0, $iv);
            
        }
        
        return $output;        
    }
    
    
  
    /*
     * Replace 
     * replace underscore (_) by a specific letter (and vice versa)
     * 
     * @param   string    $action   Replace underscore by a letter (go) or letter by underscore (back)
     * @param   string    $source   Source where replacement is done
     * @return  string
     * 
     */
    
    private static function replace($action, $source) {
    
        if ($action == "go")
        {
            $source     = str_replace(self::$rep_letter, "$", $source);
            $source     = str_replace("_", self::$rep_letter, $source);
        }
        else if ($action == "back")
        {
            $source     = str_replace(self::$rep_letter, "_", $source);
            $source     = str_replace("$", self::$rep_letter, $source);
        }
    
        return $source;
    }   
   
}
?>
