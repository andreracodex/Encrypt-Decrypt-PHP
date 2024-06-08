<?php
// Constants for Database Configuration
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '');
define('DB_NAME', 'aes');

// Create connection
$conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Function to generate ECC key pair
function generateECCKeyPair() {
    $p = 2**256 - 2**32 - 977; // Prime field for secp256k1
    $a = '0';
    $b = '7';
    $G = ['55066263022277343669578718895168534326250603453777594175500187360389116729240', '32670510020758816978083085130507043184471273380659243275938904335757337482424']; // Generator point on the curve

    $privateKey = random_int(1, $p - 1);
    $publicKey = eccMultiply($G, $privateKey, $a, $p);

    return [$privateKey, $publicKey];
}

// Function to encrypt/decrypt text using ECC
function eccEncryptDecrypt($data, $key, $isEncrypt = true) {
    $p = 2**256 - 2**32 - 977; // Prime field for secp256k1
    $a = '0';
    $b = '7';

    $G = ['55066263022277343669578718895168534326250603453777594175500187360389116729240', '32670510020758816978083085130507043184471273380659243275938904335757337482424']; // Generator point on the curve

    if (!$isEncrypt) {
        $data = base64_decode($data);
    }

    list($privateKey, $publicKey) = $key;
    $sharedKey = eccMultiply($publicKey, $privateKey, $a, $p);

    $encryptedData = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $encryptedData .= chr(ord($data[$i]) ^ $sharedKey[0]);
    }

    return $isEncrypt ? base64_encode($encryptedData) : $encryptedData;
}

// Function to perform point multiplication on an elliptic curve
function eccMultiply($point, $scalar, $a, $p) {
    if ($scalar === 0 || $point === [0, 0]) {
        return [0, 0];
    }

    $result = [0, 0];
    $addend = $point;

    while ($scalar) {
        if ($scalar & 1) {
            $result = eccAdd($result, $addend, $a, $p);
        }
        $addend = eccAdd($addend, $addend, $a, $p);
        $scalar >>= 1;
    }

    return $result;
}

// Function to perform point addition on an elliptic curve
function eccAdd($P, $Q, $a, $p) {
    if ($P == [0, 0]) return $Q;
    if ($Q == [0, 0]) return $P;

    list($x1, $y1) = $P;
    list($x2, $y2) = $Q;

    if ($x1 == $x2 && $y1 == -$y2) return [0, 0];

    if ($P == $Q) {
        $m = gmp_mod(gmp_mul(gmp_mul(3, $x1), gmp_invert(gmp_mul(2, $y1), $p)), $p);
    } else {
        $m = gmp_mod(gmp_mul(gmp_sub($y2, $y1), gmp_invert(gmp_sub($x2, $x1), $p)), $p);
    }

    $x3 = gmp_mod(gmp_sub(gmp_sub(gmp_mul($m, $m), $x1), $x2), $p);
    $y3 = gmp_mod(gmp_sub(gmp_mul($m, gmp_sub($x1, $x3)), $y1), $p);

    return [gmp_strval($x3), gmp_strval($y3)];
}

function processFile($filePath, $sharedSecret, $outputFilePath, $isEncrypt = false) {
    $fileContents = file_get_contents($filePath);
    if ($fileContents === false) {
        return false;
    }

    $processedData = eccEncryptDecrypt($fileContents, $sharedSecret, $isEncrypt);
    return file_put_contents($outputFilePath, $processedData) !== false;
}

function processFilePure($fileContents, $sharedSecret, $outputFilePath, $isEncrypt = false) {
    $fileContents = file_get_contents($fileContents);
    
    $processedData = eccEncryptDecrypt($fileContents, $sharedSecret, $isEncrypt);

    return file_put_contents($outputFilePath, $processedData) !== false;
}

// Function to handle encryption/decryption endpoints
function handleEndpoint($inputData, $inputType, $sharedSecret, $uniqueId, $conn, $isEncrypt = true) {
    // Extract Bearer token from the Authorization header
    $headers = apache_request_headers();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        return ['success' => false, 'message' => 'Authorization header is missing.'];
    }

    $authHeader = $headers['Authorization'];
    if (strpos($authHeader, 'Bearer ') !== 0) {
        http_response_code(401);
        return ['success' => false, 'message' => 'Invalid authorization header format.'];
    }

    // Validate the token (example: check against a predefined token)
    // This could also involve querying the database to validate the token
    $validToken = getBearerToken(); // Replace with your token validation logic
    $cekToken = $conn->prepare("SELECT * FROM sess WHERE token = ?");
    $cekToken->bind_param("s", $validToken);
    $cekToken->execute();
    $result = $cekToken->get_result();

    if ($result->num_rows > 0) {
        $validToken2 = $result->fetch_assoc();
        $validTokens = $validToken2['token'];    
    } else {
        return ['success' => false, 'message' => 'No Session Found.'];
    }
    // var_dump($validToken, $validTokens);
    if ($validToken !== $validTokens) {
        http_response_code(403);
        return ['success' => false, 'message' => 'Invalid token.'];
    }

    // Proceed with the main operations
    if (empty($uniqueId)) {
        http_response_code(400);
        return ['success' => false, 'message' => 'Unique ID is required.'];
    }

    $fileExtension = '.nathan';
    $outputFilePath = '';
    $resultData = '';
    $token = $_POST['token'] ?? '';

    if ($inputType === 'file') {
        $filename = $_FILES["file"]["name"];
        $filename = str_replace(' ', '', $filename); // Remove spaces
        // Optionally, you can also remove other blank characters like tabs and newlines
        $filename = preg_replace('/\s+/', '', $filename);
        $outputFilePath = ($isEncrypt ? 'encrypt/' . $filename . $fileExtension : 'decrypt/' . preg_replace('/\.\w+$/', '', $filename));

        $processResult = processFile($inputData, $sharedSecret, $outputFilePath, $isEncrypt);
        if (!$processResult) {
            return [
                'success' => false, 
                'message' => 'Error processing file.',
            ];
        }
    } elseif ($inputType === 'text') {
        $filename = 'Text';
        $outputFilePath = 'String.txt';
        $resultData = eccEncryptDecrypt($inputData, $sharedSecret, $isEncrypt);
        if (!$resultData) {
            return [
                'success' => false, 
                'message' => 'Error processing text input.'
            ];
        }
    } else {
        http_response_code(400);
        return ['success' => false, 'message' => 'Invalid input type. Supported types are "file" and "text".'];
    }

    if ($isEncrypt) {
        $uuid = generateUuid();
        $sql = "INSERT INTO xfiles (action, file_name, output_file_path, shared_secret, unique_id, uuid, values_data, type_file, token) 
                VALUES ('encrypt', '$filename', '$outputFilePath', '$sharedSecret', '$uniqueId', '$uuid', '$resultData', '$inputType', '$token')";
        $conn->query($sql);
    } else {
        $sql = "SELECT * FROM xfiles WHERE unique_id = '$uniqueId'";
        $result = $conn->query($sql);
        if ($result && $row = $result->fetch_assoc()) {
            $uuid = $row['uuid'];
            if ($uniqueId !== $row['unique_id']) {
                return ['success' => false, 'message' => 'Unique ID provided does not match the one associated with the file.'];
            }
        } else {
            return ['success' => false, 'message' => 'No data found for the provided unique ID.'];
        }
    }

    return [
        'success' => true,
        'uuid' => $uuid,
        'message' => 'Data ' . urlencode($isEncrypt ? 'encrypted' : 'decrypted') . ' successfully!',
        'output' => $outputFilePath,
        'text' => $resultData ?? '',
        'file' => 'https://encrypt-decrypt.test/api/' .$outputFilePath ?? ''
    ];
}

// Example token generation function
function generateToken() {
    return bin2hex(random_bytes(16));
}

function getBearerToken() {
    $headers = null;

    // Check for Apache or FastCGI headers
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER["Authorization"]);
    } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) { // Nginx or FastCGI
        $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        // Get the Authorization header from the apache headers
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }

    // Bearer token starts with "Bearer "
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            return $matches[1];
        }
    }
    return null;
}

function handleEndpointTrue($inputData, $inputType, $sharedSecret, $uniqueId, $conn, $isEncrypt = false) {
    if (empty($uniqueId)) {
        http_response_code(400);
        return ['success' => false, 'message' => 'Unique ID is required.'];
    }

    // var_dump($inputType);
    if ($inputType === 'text') {
        $sql = "SELECT * FROM xfiles WHERE unique_id = '$uniqueId'";
        $result = $conn->query($sql);
        $row = $result->fetch_assoc();
        
        if ($uniqueId !== $row['unique_id']) {
            return ['success' => false, 'message' => 'Unique ID provided does not match the one associated with the file.'];
        } else if($sharedSecret !== $row['shared_secret']) {
            return ['success' => false, 'message' => 'Shared Secret Not Same, You Put Wrong Key'];
        } else {
            $hasilpure = $row['values_data'];
            $result_hasil = eccEncryptDecrypt($hasilpure, $sharedSecret, $isEncrypt);

            return [
                'success' => true,
                'message' => 'Decrypt.',
                'output' => $result_hasil,
                'result' => json_decode($result_hasil)
            ];
        }

    } else if ($inputType === 'file') {
        $sql = "SELECT * FROM xfiles WHERE unique_id = '$uniqueId'";
        $result = $conn->query($sql);
        $row = $result->fetch_assoc();

        $filename = $row["file_name"];
        $uuid = $row["uuid"];

        $pathInfo = pathinfo($filename);
        $newFilename = $pathInfo['filename'].'.'.$pathInfo['extension'].'.nathan';
        $filePath = 'https://encrypt-decrypt.test/api/encrypt/'.$newFilename;
        
        $filename = str_replace(' ', '', $filename); // Remove spaces

        $filename = preg_replace('/\s+/', '', $filename);
        $outputFilePath = 'decrypt/'. $filename;

        $processResult = processFilePure($filePath, $sharedSecret, $outputFilePath, $isEncrypt);
        if (!$processResult) {
            return [
                'success' => false, 
                'message' => 'Error processing file.',
            ];
        } else {

            return [
                'uuid' => $uuid,
                'success' => true,
                'message' => 'Data ' . urlencode($isEncrypt ? 'encrypted' : 'decrypted') . ' successfully!',
                'output' => $outputFilePath,
                'text' => $processResult ?? '',
                'file' => 'https://encrypt-decrypt.test/api/' .$outputFilePath ?? ''
            ];
        }
    } else {
        http_response_code(400);
        return ['success' => false, 'message' => 'Invalid input type. Supported types are "file" and "text".'];
    }
}

// Function to generate UUID
function generateUuid() {
    return sprintf(
        '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

// Handle incoming API requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $sharedSecret = $_POST['shared_secret'] ?? '';
    $uniqueId = $_POST['uniqueid'] ?? '';
    // $idUser = $_POST['id_user'] ?? '';

    if ($action === 'encrypt' || $action === 'decrypt') {
        $isEncrypt = $action === 'encrypt';
        $inputType = '';

        if (isset($_FILES['file']['error']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
            $inputData = $_FILES['file']['tmp_name'];
            $inputType = 'file';
        } elseif (isset($_POST['text'])) {
            $inputData = $_POST['text'];
            $inputType = 'text';
        } else {
            die(json_encode(['success' => false, 'message' => 'Invalid input: No file or text provided.']));
        }

        $result = handleEndpoint($inputData, $inputType, $sharedSecret, $uniqueId, $conn, $isEncrypt);
        echo $prettyJson = json_encode($result, JSON_PRETTY_PRINT);

    } else if ($action === 'decryptpure') {

        if ($_POST['type'] === 'text') {
            $inputData = 'text';
            $inputType = 'text';
        }else if ($_POST['type'] === 'file') {
            $inputData = 'file';
            $inputType = 'file';
        } else {
            die(json_encode(['success' => false, 'message' => 'Invalid input: No file or text provided.']));
        }

        $result = handleEndpointTrue($inputData, $inputType, $sharedSecret, $uniqueId, $conn);
        echo json_encode($result);
        exit();
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid action.']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
}

// Close database connection
$conn->close();
