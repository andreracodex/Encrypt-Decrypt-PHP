<?php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Your encryption code...
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

// Assuming key exchange is already done and we have the shared secret
if(isset($_POST['enckey'])){
    $sharedSecret = $_POST['enckey'];
}elseif(isset($_POST['deckey'])){
    $sharedSecret = $_POST['deckey'];
}else{
    $sharedSecret = '12345';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $file = $_FILES['file'];

    if (isset($_FILES['file'])) {
        $filePath = $file['tmp_name'];
        $action = $_POST['action'];

        $path_parts = pathinfo($_FILES["file"]["name"]);
        $filename = $_FILES["file"]["name"];
        $extension = $path_parts['extension'];

        if ($action === 'encrypt') {
            $name = preg_replace('/\.\w+$/', '', $file['name']);
            $fileExtension = '.nathan';
            $outputFilePath = 'encrypt/' .$name.'.'.$extension.$fileExtension;
            $encryptionResult = encryptFile($filePath, $sharedSecret, $outputFilePath);

            // save original file
            $target = 'encrypt/original/'.$filename;
            move_uploaded_file($_FILES['file']['tmp_name'], $target);

            if ($encryptionResult === false) {
                $message = "Error encrypting file or writing encrypted data to file.";
            } else {
                $message = "File encrypted successfully! <a href='$outputFilePath' class='alert-link'>Download encrypted file</a>";
            }

        } elseif ($action === 'decrypt') {
            $newFilename = str_replace('.'.$extension, '', $filename);
            $outputFilePath = 'decrypt/'. $newFilename;
            $decryptionResult = decryptFile($filePath, $sharedSecret, $outputFilePath);

            if ($decryptionResult === false) {
                $message = "Error decrypting file or writing decrypted data to file.";
            } else {
                $message = "File decrypted successfully! <a href='$outputFilePath' class='alert-link'>Download decrypted file</a>";
            }
        }
    } else {
        $message = "Please provide a file.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Encrypt File</title>
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">
    <link href="css/styledash.css" rel="stylesheet">
</head>
<body>
    <div class="wrapper">
        <?php include 'sidebar.php'; ?>

        <div id="content">
            <div class="container mt-5">
                <h1 class="mb-4">Encrypt Files (ECC)</h1>
                <?php if (isset($message)): ?>
                    <div class="alert alert-info" role="alert">
                        <?= $message ?>
                    </div>
                <?php endif; ?>
                <div class="card mb-4">
                    <div class="card-header">
                        Encrypt Files
                    </div>
                    <div class="card-body">
                        <form method="post" action="encrypt-ecc.php" enctype="multipart/form-data">
                            <input type="hidden" name="action" value="encrypt">
                            <div class="mb-3">
                                <label for="file" class="form-label">Encrypt Key:</label>
                                <input type="text" id="enckey" name="enckey" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label for="file" class="form-label">File Upload:</label>
                                <input type="file" id="file" name="file" class="form-control" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Encrypt</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.10.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
