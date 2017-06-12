<?php
  // this is only for test. Generally, public key use not when decrypt.

  error_reporting(E_ALL);
  ini_set("display_errors", 1);

  //Block size for encryption block cipher
  $ENCRYPT_BLOCK_SIZE = 200;// this for 2048 bit key for example, leaving some room

  //Block size for decryption block cipher
  $DECRYPT_BLOCK_SIZE = 256;// this again for 2048 bit key

  // For encryption we would use:
  function encrypt_RSA($plainData, $privatePEMKey)
  {
	global $ENCRYPT_BLOCK_SIZE;

    $encrypted = '';
    $plainData = str_split($plainData, $ENCRYPT_BLOCK_SIZE);
    foreach($plainData as $chunk)
    {
      $partialEncrypted = '';

      //using for example OPENSSL_PKCS1_PADDING as padding
      $encryptionOk = openssl_private_encrypt($chunk, $partialEncrypted, $privatePEMKey, OPENSSL_PKCS1_PADDING);

      if($encryptionOk === false){return false;}//also you can return and error. If too big this will be false
      $encrypted .= $partialEncrypted;
    }
    return base64_encode($encrypted);//encoding the whole binary String as MIME base 64
  }

  //For decryption we would use:
  function decrypt_RSA_Impl($publicPEMKey, $data, $useBlockSize=true)
  {
	global $DECRYPT_BLOCK_SIZE;

    $decrypted = '';

    //decode must be done before spliting for getting the binary String
    if($useBlockSize == true) {
      $data = str_split(base64_decode($data), $DECRYPT_BLOCK_SIZE);
    } else {
      $data[] = base64_decode($data);
    }

    foreach($data as $chunk)
    {
      $partial = '';

      //be sure to match padding
      $decryptionOK = openssl_public_decrypt($chunk, $partial, $publicPEMKey, OPENSSL_PKCS1_PADDING);

      if($decryptionOK === false){
		   echo "failed.\n";
	  }

      //here also processed errors in decryption. If too big this will be false
      $decrypted .= $partial;
    }
    return $decrypted;
  }

  function decrypt_RSA($publicPEMKey, $data) {
    decrypt_RSA_Impl($publicPEMKey, $data);
  }

  function decrypt_RSA_NoSize($publicPEMKey, $data) {
    decrypt_RSA_Impl($publicPEMKey, $data, false);
  }
?>
  
<h1>GET_HINT_TEST</h1>

<?php
$pubkey = file_get_contents('pubkey.pem');
$krpr = file_get_contents('krpr-b64.bin');
$ka = file_get_contents('ka-b64.bin');

echo "<pre>";

if(!empty($pubkey)) {
	echo "Load Pubkey... Ok\n\n";
}

echo $pubkey;

echo "\n\n";

echo "Get hint 1 testing...\n";
echo decrypt_RSA($pubkey, $krpr);
echo "\n";

echo "Not use block size\n";
echo decrypt_RSA_NoSize($pubkey, $krpr) ? "success.\n" : "failed.\n";
echo "\n";

echo "Get hint 2 testing...\n";
echo decrypt_RSA($pubkey, $ka);
echo "\n";

echo "Not use block size\n";
echo decrypt_RSA_NoSize($pubkey, $ka) ? "success.\n" : "failed.\n";
echo "\n";

echo "</pre>";
?>
