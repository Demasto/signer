<?php
/*

/usr/bin/php81 -l $HOME/bots.vardi.ru/www/mantis-tg/common.inc.php
/usr/bin/php81 -q $HOME/bots.vardi.ru/www/mantis-tg/common.inc.php

tail -n50 $HOME/_logs/bots.vardi.ru/bots.vardi.ru.error_log

 */

$input = file_get_contents('php://input');


header('Content-Type: application/json; charset=utf-8');

/**
 * Проверим, что в параметре "c" (certificate) указан номер сертификата, который состоит только из латинских букв и цифр
 * а также длина номера сертификата не более 256 символов.
 * 
 */
if( ! is_null( $_GET[ 'c' ] ) && ctype_alnum( $_GET[ 'c' ] ) && mb_strlen($_GET[ 'c' ]) < 257 ) 
{
	/**
	 * Если номер сертификата есть, проверим, переданы ли POST-данные для сохранения
	 */
	if( empty( $input ) )
	{

		// Данных для сохранения нет, извлекаем даные сертификата и отдаем их на клиента
		echo get_data_by_certificate(cert: $_GET['c']);
	}else{
		// Имеются данные для сохранения - сохраняем их и отдаем результат сохранения клиенту
		echo set_data_by_certificate(cert: $_GET['c'], input: $input);
	}
}else{
	// ошибка проверки номера сертификата
	echo json_encode(['result' => false, 'error' => 'номер сертификата содежит недопустимые символы.']);
}

function get_data_by_certificate($cert){
	$hash = make_hash('Dr0Hf1R9magLvSMk85Ki3R4U6WYYw3YsZ8shLPF7H40=' . $cert . 'ofPk0CAU5Ikr048+5jwqNpNw66M2J9LI8zn1jfwHcGY=');
	
	$response = request(cert: $cert, hash: $hash);
	if(isset($response['result']) && isset($response['data']) && $response['result'] == true){
		return $response['data'] == 'none' ? '{}' : secured_decrypt( $response['data'] );
	}else{
		return json_encode(['result' => false]);
	}
}

function set_data_by_certificate($cert, $input){

	$crypto_input = secured_encrypt($input);

	$hash = make_hash('jcsn3AyWLVJxbgkzgMPpZniUawYBTLo/1AepJUCuCdk=' . $cert . 'cLTzeC+VHcQ7QKCfWwPkfHpGHZIXJDqqgd05Eh6vA98=' . $crypto_input);

	$response = request(cert: $cert, hash: $hash, input: $crypto_input);

	if(isset($response['result']) && $response['result'] == true){
		return json_encode(['result' => true]);
	}else{
		return json_encode(['result' => false]);
	}
}

function secured_encrypt($data)
{
	$first_key = base64_decode('1azu7BOsDvs0U6/KFGltjREqr3MeXmfNJ5Z/hxxscMg=');
	$second_key = base64_decode('HKgMscVVkUxyLo5HC3sthK7su+EjNtXWqwx+BHrGIWLUCUXqTtc9ECC/XxJItxCGG7p6qVO3VzJ2zgaFL9eWSw==');    
	    
	$method = "aes-256-cbc";    
	$iv_length = openssl_cipher_iv_length($method);
	$iv = openssl_random_pseudo_bytes($iv_length);
	        
	$first_encrypted = openssl_encrypt($data,$method,$first_key, OPENSSL_RAW_DATA ,$iv);    
	$second_encrypted = hash_hmac('sha3-512', $first_encrypted, $second_key, TRUE);
	            
	$output = base64_encode($iv.$second_encrypted.$first_encrypted);    
	return $output;
}

function secured_decrypt($input)
{
	$first_key = base64_decode('1azu7BOsDvs0U6/KFGltjREqr3MeXmfNJ5Z/hxxscMg=');
	$second_key = base64_decode('HKgMscVVkUxyLo5HC3sthK7su+EjNtXWqwx+BHrGIWLUCUXqTtc9ECC/XxJItxCGG7p6qVO3VzJ2zgaFL9eWSw==');             
	$mix = @base64_decode($input);
	
	$method = "aes-256-cbc";    
	$iv_length = openssl_cipher_iv_length($method);
	            
	$iv = substr($mix,0,$iv_length);
	$second_encrypted = substr($mix,$iv_length,64);
	$first_encrypted = substr($mix,$iv_length+64);
	            
	$data = openssl_decrypt($first_encrypted,$method,$first_key,OPENSSL_RAW_DATA,$iv);
	$second_encrypted_new = hash_hmac('sha3-512', $first_encrypted, $second_key, TRUE);
	    
	if (hash_equals($second_encrypted,$second_encrypted_new)){
		return $data;
	}

	return json_encode(false);
}


function make_hash($s){
	for($i=0;$i<100;$i++){
		$s = hash_hmac('sha256', $s, $s);
	}
	return $s;
}

function request( $cert, $hash, $input = null )
{
	$c = curl_init("https://vardi.ru/napodpisi/api.php");
	$data = json_encode(['cert' => $cert, 'hash' => $hash, 'input' => $input]);
	curl_setopt($c, CURLOPT_CUSTOMREQUEST, "POST");
	curl_setopt($c, CURLOPT_POSTFIELDS, $data);
	curl_setopt($c, CURLOPT_RETURNTRANSFER, true);
	$response = curl_exec($c);
	curl_close($c);
	//var_dump($response);
	if(!$response){
		return ['result' => false, 'error' => 'Ошибка связи с сервером хранения, попробуйте еще раз позже.'];
	}
	return json_decode($response, 1);
}

function filterCertificateNumber($cert){
	return preg_replace('/[^ a-zA-Z\d]/ui', '', $cert );
}
