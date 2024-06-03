<?php
// Database Configuration
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "aes";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Function to generate ECC key pair
function generateECCKeyPair()
{
    // Prime field p and elliptic curve parameters
    $p = 2**256 - 2**32 - 977; // Prime field for secp256k1
    $a = '0';
    $b = '7';
    $Gx = '55066263022277343669578718895168534326250603453777594175500187360389116729240';
    $Gy = '32670510020758816978083085130507043184471273380659243275938904335757337482424';
    $G = array($Gx, $Gy); // Generator point on the curve

    // Generate private key
    $privateKey = random_int(1, $p - 1);

    // Calculate public key: publicKey = privateKey * G
    $publicKey = eccMultiply($G, $privateKey, $a, $p);

    return [$privateKey, $publicKey];
}

// Function to perform point multiplication on an elliptic curve
function eccMultiply($point, $scalar, $a, $p)
{
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
function eccAdd($P, $Q, $a, $p)
{
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

// Function to find modular inverse
function inverse($k, $p)
{
    return pow($k, $p - 2, $p);
}

// Function to XOR encrypt the data with a key
function xorEncrypt($data, $key)
{
    $keyLength = strlen($key);
    $output = '';
    for ($i = 0, $j = 0; $i < strlen($data); $i++, $j = ($j + 1) % $keyLength) {
        $output .= $data[$i] ^ $key[$j];
    }
    return $output;
}

// Function to XOR decrypt the data with a key (same as encrypt)
function xorDecrypt($data, $key)
{
    return xorEncrypt($data, $key);
}

// Function to encrypt the file using XOR with the shared secret
function encryptFile($filePath, $sharedSecret, $outputFilePath)
{
    $fileContents = file_get_contents($filePath);
    if ($fileContents === false) {
        return false;
    }
    $encryptedData = xorEncrypt($fileContents, $sharedSecret);
    if (file_put_contents($outputFilePath, $encryptedData) === false) {
        return false;
    }
    return true;
}

// Function to decrypt the file using XOR with the shared secret
function decryptFile($encryptedFilePath, $sharedSecret, $outputFilePath)
{
    $encryptedData = file_get_contents($encryptedFilePath);
    if ($encryptedData === false) {
        return false;
    }
    $decryptedData = xorDecrypt($encryptedData, $sharedSecret);
    if (file_put_contents($outputFilePath, $decryptedData) === false) {
        return false;
    }
    return true;
}

// Function to handle encryption endpoint
function encryptEndpoint($filePath, $sharedSecret, $uniqueId, $conn)
{
    if (empty($uniqueId)) {
        http_response_code(400);
        return [
            'success' => false,
            'message' => 'Unique ID is required.'
        ];
    }

    $file = '.nathan';
    $filename = $_FILES["file"]["name"];
    $outputFilePath = 'encrypt/' . $filename . $file; // Define your output file path here

    // Create UUID file
    $uuid = generateUuid();

    // Insert request details into the database
    $sql = "INSERT INTO xfiles (action, file_name, output_file_path, shared_secret, unique_id, uuid) VALUES ('encrypt', '$filename', '$outputFilePath', '$sharedSecret', '$uniqueId', '$uuid')";
    $conn->query($sql);

    // Handle file encryption
    $encryptionResult = encryptFile($filePath, $sharedSecret, $outputFilePath);

    if ($encryptionResult === false) {
        return [
            'success' => false,
            'message' => 'Error encrypting file or writing encrypted data to file.'
        ];
    } else {
        return [
            'success' => true,
            'message' => 'File encrypted successfully!',
            'outputFilePath' => $outputFilePath
        ];
    }
}

// Function to handle decryption endpoint
function decryptEndpoint($filePath, $sharedSecret, $uniqueId, $conn)
{
    if (empty($uniqueId)) {
        http_response_code(400);
        return [
            'success' => false,
            'message' => 'Unique ID is required.'
        ];
    }

    $filename = $_FILES["file"]["name"];
    $extension = '.nathan';
    $newFilename = str_replace($extension, '', $filename);
    $outputFilePath = 'decrypt/' . $newFilename; // Define your output file path here
    try {
        // Fetch the unique_id associated with the filename from the database
        $sql = "SELECT * FROM xfiles WHERE unique_id = '$uniqueId'";
        $result = $conn->query($sql);

        // Check if the unique_id
        if ($result && $row = $result->fetch_assoc()) {
            $dbUniqueId = $row['unique_id'];
        } else {
            throw new Exception("No data uniqueid found in the database");
        }

        // Check if the provided unique_id matches the one stored in the database
        if ($uniqueId !== $dbUniqueId) {
            return [
                'success' => false,
                'message' => 'Unique ID provided does not match the one associated with the file.',
            ];
        }

        // Continue with decryption if the unique_id matches

        // Handle file decryption
        $decryptionResult = decryptFile($filePath, $sharedSecret, $outputFilePath);

        if ($decryptionResult === false) {
            return [
                'success' => false,
                'message' => 'Error decrypting file or writing decrypted data to file.'
            ];
        } else {
            return [
                'success' => true,
                'message' => 'File decrypted successfully!',
                'outputFilePath' => $outputFilePath
            ];
        }
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => $e->getMessage()
        ];
    }
}

function generateUuid()
{
    return sprintf(
        '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        // 32 bits for "time_low"
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),

        // 16 bits for "time_mid"
        mt_rand(0, 0xffff),

        // 16 bits for "time_hi_and_version",
        // four most significant bits holds version number 4
        mt_rand(0, 0x0fff) | 0x4000,

        // 16 bits, 8 bits for "clk_seq_hi_res",
        // 8 bits for "clk_seq_low",
        // two most significant bits holds zero and one for variant DCE1.1
        mt_rand(0, 0x3fff) | 0x8000,

        // 48 bits for "node"
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff)
    );
}

// Handle incoming API requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get the action from the request
    $action = isset($_POST['action']) ? $_POST['action'] : '';

    // Check the action and handle accordingly
    if ($action === 'encrypt') {
        // Check if the file was uploaded successfully
        if (!isset($_FILES['file']['error']) || is_array($_FILES['file']['error'])) {
            die(json_encode([
                'success' => false,
                'message' => 'Invalid file upload.'
            ]));
        }

        // Get the shared secret from the request
        $sharedSecret = isset($_POST['shared_secret']) ? $_POST['shared_secret'] : '';

        // Get the uniqueid from the request
        $uniqueId = isset($_POST['uniqueid']) ? $_POST['uniqueid'] : '';

        // Handle file encryption
        $result = encryptEndpoint($_FILES['file']['tmp_name'], $sharedSecret, $uniqueId, $conn);
        echo json_encode($result);
    } elseif ($action === 'decrypt') {
        // Check if the file was uploaded successfully
        if (!isset($_FILES['file']['error']) || is_array($_FILES['file']['error'])) {
            die(json_encode([
                'success' => false,
                'message' => 'Invalid file upload.'
            ]));
        }

        // Get the shared secret from the request
        $sharedSecret = isset($_POST['shared_secret']) ? $_POST['shared_secret'] : '';

        // Get the uniqueid from the request
        $uniqueId = isset($_POST['uniqueid']) ? $_POST['uniqueid'] : '';

        // Handle file decryption
        $result = decryptEndpoint($_FILES['file']['tmp_name'], $sharedSecret, $uniqueId, $conn);
        echo json_encode($result);
    } else {
        // Invalid action
        echo json_encode([
            'success' => false,
            'message' => 'Invalid action.'
        ]);
    }
} else {
    // Invalid request method
    echo json_encode([
        'success' => false,
        'message' => 'Invalid request method.'
    ]);
}

// Close database connection
$conn->close();
