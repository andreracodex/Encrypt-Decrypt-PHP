<?php

// Function to generate ECC key pair
function generateECCKeyPair() {
    // For simplicity, we'll use a small prime number
    $p = 23; // A small prime number
    $a = 1; // Curve parameter a
    $b = 1; // Curve parameter b
    $G = [5, 1]; // Generator point on the curve

    // Generate private key
    $privateKey = random_int(1, $p - 1);
    
    // Calculate public key: publicKey = privateKey * G
    $publicKey = eccMultiply($G, $privateKey, $a, $p);

    return [$privateKey, $publicKey];
}

// Function to perform point multiplication on an elliptic curve
function eccMultiply($point, $scalar, $a, $p) {
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

    if ($P[0] == $Q[0] && $P[1] == -$Q[1]) return [0, 0];

    if ($P == $Q) {
        $m = (3 * $P[0] * $P[0] + $a) * inverse(2 * $P[1], $p) % $p;
    } else {
        $m = ($Q[1] - $P[1]) * inverse($Q[0] - $P[0], $p) % $p;
    }

    $x3 = ($m * $m - $P[0] - $Q[0]) % $p;
    $y3 = ($m * ($P[0] - $x3) - $P[1]) % $p;

    return [$x3, $y3];
}

// Function to find modular inverse
function inverse($k, $p) {
    return pow($k, $p - 2, $p);
}

// Function to XOR encrypt the data with a key
function xorEncrypt($data, $key) {
    $keyLength = strlen($key);
    $output = '';
    for ($i = 0, $j = 0; $i < strlen($data); $i++, $j = ($j + 1) % $keyLength) {
        $output .= $data[$i] ^ $key[$j];
    }
    return $output;
}

// Function to XOR decrypt the data with a key (same as encrypt)
function xorDecrypt($data, $key) {
    return xorEncrypt($data, $key);
}

// Function to encrypt the file using XOR with the shared secret
function encryptFile($filePath, $sharedSecret, $outputFilePath) {
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
function decryptFile($encryptedFilePath, $sharedSecret, $outputFilePath) {
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
function encryptEndpoint($filePath, $sharedSecret) {
    $file = '.nathan';
    $filename = $_FILES["file"]["name"];
    $outputFilePath = 'encrypt/'.$filename.$file; // Define your output file path here
    $encryptionResult = encryptFile($filePath, $sharedSecret, $outputFilePath);

    if ($encryptionResult === false) {
        return ['success' => false, 'message' => 'Error encrypting file or writing encrypted data to file.'];
    } else {
        return ['success' => true, 'message' => 'File encrypted successfully!', 'outputFilePath' => $outputFilePath];
    }
}

// Function to handle decryption endpoint
function decryptEndpoint($filePath, $sharedSecret) {
    $filename = $_FILES["file"]["name"];
    $extension = '.nathan';
    $newFilename = str_replace($extension, '', $filename);
    $outputFilePath = 'decrypt/'.$newFilename; // Define your output file path here
    $decryptionResult = decryptFile($filePath, $sharedSecret, $outputFilePath);

    if ($decryptionResult === false) {
        return ['success' => false, 'message' => 'Error decrypting file or writing decrypted data to file.'];
    } else {
        return ['success' => true, 'message' => 'File decrypted successfully!', 'outputFilePath' => $outputFilePath];
    }
}

// Handle incoming API requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get the action from the request
    $action = isset($_POST['action']) ? $_POST['action'] : '';

    // Check the action and handle accordingly
    if ($action === 'encrypt') {
        // Check if the file was uploaded successfully
        if (!isset($_FILES['file']['error']) || is_array($_FILES['file']['error'])) {
            die(json_encode(['success' => false, 'message' => 'Invalid file upload.']));
        }

        // Get the shared secret from the request
        $sharedSecret = isset($_POST['shared_secret']) ? $_POST['shared_secret'] : '';

        // Handle file encryption
        $result = encryptEndpoint($_FILES['file']['tmp_name'], $sharedSecret);
        echo json_encode($result);
    } elseif ($action === 'decrypt') {
        // Check if the file was uploaded successfully
        if (!isset($_FILES['file']['error']) || is_array($_FILES['file']['error'])) {
            die(json_encode(['success' => false, 'message' => 'Invalid file upload.']));
        }

        // Get the shared secret from the request
        $sharedSecret = isset($_POST['shared_secret']) ? $_POST['shared_secret'] : '';

        // Handle file decryption
        $result = decryptEndpoint($_FILES['file']['tmp_name'], $sharedSecret);
        echo json_encode($result);
    } else {
        // Invalid action
        echo json_encode(['success' => false, 'message' => 'Invalid action.']);
    }
} else {
    // Invalid request method
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
}

?>
