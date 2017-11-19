<?php

/************************************************************************************************************************************************
 *
 * Class:  Cryptor
 * PHP Encryption and decryption class with open_ssl
 * Works also with larger text (because text is split in smaller parts)
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
     * 
     *
     * @param      string       $plain_txt        Text, to be encrypted
     * @param      string       $encrypted_txt    Text, to be decrypted
     * @param      string       $secretkey        Optional, override with (static private) property 
     * 
     * @property   int          $unique_nr        Amount of random characters put in front en behind encrypted string + used as salt
     * @property   int          $strspit_nr       Amount of characters to split source (<= 400!), open_ssl cannot encrypt large files
     * @property   string       $rep_letter       Letter used to replace underscore (prevent detecting str_splits)
     * @property   string       $secret_key       Secret_key (sha512 hashvalue is created from this string)
     * @property   string       $secret_iv        Secret_iv (sha512 hashvalue (16 chars) is created from this string)
     * 
     * @return     string       Encrypted or decrypted text
     * 
     * @author     Peter Muller <petermuller71@gmail.com>
     * @version    1.03
     *
     */
    
    static private $strspit_nr = 350;                     // smaller than 400 characters!                    
    static private $rep_letter = 'b';                     // change this (any letter, small or Capital)!
    static private $secret_key = 'This is my secret key'; // change this!
    static private $secret_iv  = 'This is my secret iv';  // change this!

    
    
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
       $salt      = substr(hash('sha512', $plain_txt), 0, 10);     
       $plain_txt = $salt.$plain_txt;
       
       // $plain_text should be split in smaller parts and encrypted seperatly
      
       $arr = str_split($plain_txt, self::$strspit_nr);
       foreach ($arr as $v) { $encrypted_txt .= substr(self::doEncryptDecrypt('encrypt', $secretkey, $v), 0, -2)."_"; }
       
       $encrypted_txt = substr($encrypted_txt, 0, -1);
       
       // smaller parts were glued together with underscore (_) and replaced by a letter 
       
       $encrypted_txt = self::replace("go", $encrypted_txt);
       
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
       
       // smaller parts were glued together with underscore (_) and replaced by a letter      
       
       $encrypted_txt   = self::replace("back", $encrypted_txt);

       // $encrypted_txt should be split in smaller parts and decrypted seperatly
       
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
        
        // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
        $iv = substr(hash('sha512', self::$secret_iv), 0, 16);
        
        if ( $action == 'encrypt' ) {
        
            $output = openssl_encrypt($source, "AES-256-CBC", $secretkey, 0, $iv);
            $output = base64_encode($output);
        
        } else if( $action == 'decrypt' ) {
        
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
?><?php

/************************************************************************************************************************************************
 *
 * Class:  Cryptor
 * PHP Encryption and decryption class with open_ssl
 * Works also with larger text (because text is split in smaller parts)
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
     * 
     *
     * @param      string       $plain_txt        Text, to be encrypted
     * @param      string       $encrypted_txt    Text, to be decrypted
     * @param      string       $secretkey        Optional, override with (static private) property 
     * 
     * @property   int          $unique_nr        Amount of random characters put in front en behind encrypted string + used as salt
     * @property   int          $strspit_nr       Amount of characters to split source (<= 400!), open_ssl cannot encrypt large files
     * @property   string       $rep_letter       Letter used to replace underscore (prevent detecting str_splits)
     * @property   string       $secret_key       Secret_key (sha512 hashvalue is created from this string)
     * @property   string       $secret_iv        Secret_iv (sha512 hashvalue (16 chars) is created from this string)
     * 
     * @return     string       Encrypted or decrypted text
     * 
     * @author     Peter Muller <petermuller71@gmail.com>
     * @version    1.03
     *
     */
    
    static private $strspit_nr = 350;                     // smaller than 400 characters!                    
    static private $rep_letter = 'b';                     // change this (any letter, small or Capital)!
    static private $secret_key = 'This is my secret key'; // change this!
    static private $secret_iv  = 'This is my secret iv';  // change this!

    
    
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
       $salt      = substr(hash('sha512', $plain_txt), 0, 10);     
       $plain_txt = $salt.$plain_txt;
       
       // $plain_text should be split in smaller parts and encrypted seperatly
      
       $arr = str_split($plain_txt, self::$strspit_nr);
       foreach ($arr as $v) { $encrypted_txt .= substr(self::doEncryptDecrypt('encrypt', $secretkey, $v), 0, -2)."_"; }
       
       $encrypted_txt = substr($encrypted_txt, 0, -1);
       
       // smaller parts were glued together with underscore (_) and replaced by a letter 
       
       $encrypted_txt = self::replace("go", $encrypted_txt);
       
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
       
       // smaller parts were glued together with underscore (_) and replaced by a letter      
       
       $encrypted_txt   = self::replace("back", $encrypted_txt);

       // $encrypted_txt should be split in smaller parts and decrypted seperatly
       
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
        
        // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
        $iv = substr(hash('sha512', self::$secret_iv), 0, 16);
        
        if ( $action == 'encrypt' ) {
        
            $output = openssl_encrypt($source, "AES-256-CBC", $secretkey, 0, $iv);
            $output = base64_encode($output);
        
        } else if( $action == 'decrypt' ) {
        
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
