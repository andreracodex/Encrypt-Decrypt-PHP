<?php
// Function to encrypt the file
function encryptFile($filePath, $key, $outputFilePath) {
    $iv = random_bytes(16); // AES-256-CBC uses a 16-byte IV
    $fileContents = file_get_contents($filePath);
    if ($fileContents === false) {
        return false; // Error reading file
    }
    $encryptedData = openssl_encrypt($fileContents, 'AES-256-CBC', $key, 0, $iv);
    if ($encryptedData === false) {
        return false; // Error encrypting data
    }
    $encryptedDataWithIV = base64_encode($iv . $encryptedData);
    if (file_put_contents($outputFilePath, $encryptedDataWithIV) === false) {
        return false; // Error writing encrypted data to file
    }
    return true; // Encryption successful
}

// Function to decrypt the file
function decryptFile($encryptedData, $key, $outputFilePath) {
    $data = base64_decode($encryptedData);
    if ($data === false || strlen($data) < 16) {
        return false; // Invalid encrypted data
    }
    $iv = substr($data, 0, 16);
    $encryptedText = substr($data, 16);
    $decryptedData = openssl_decrypt($encryptedText, 'AES-256-CBC', $key, 0, $iv);
    if ($decryptedData === false) {
        return false; // Error decrypting data
    }
    if (file_put_contents($outputFilePath, $decryptedData) === false) {
        return false; // Error writing decrypted data to file
    }
    return true; // Decryption successful
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $key = $_POST['key'];
    $file = $_FILES['file'];

    if ($key && $file) {
        $filePath = $file['tmp_name'];
        $action = $_POST['action'];

        $path_parts = pathinfo($_FILES["file"]["name"]);
        $filename = $_FILES["file"]["name"];
        $extension = $path_parts['extension'];

        if ($action === 'encrypt') {
            $name = preg_replace('/\.\w+$/', '', $file['name']);
            $fileExtension = '.nathan';
            $outputFilePath = 'encrypt/' .$name.'.'.$extension.$fileExtension;
            $encryptionResult = encryptFile($filePath, $key, $outputFilePath);

            // save original file
            $target = 'encrypt/original/'.$filename;
            move_uploaded_file( $_FILES['file']['tmp_name'], $target);

            if ($encryptionResult === false) {
                $message = "Error encrypting file or writing encrypted data to file.";
            } else {
                $message = "File encrypted successfully! <a href='$outputFilePath' class='alert-link'>Download encrypted file</a>";
            }

        } elseif ($action === 'decrypt') {

            $encryptedData = file_get_contents($filePath);
            if ($encryptedData === false) {
                $message = "Error reading encrypted file.";
                
            } else {
                $newFilename = str_replace('.'.$extension, '', $filename);
                $outputFilePath = 'decrypt/'. $newFilename;
                $decryptionResult = decryptFile($encryptedData, $key, $outputFilePath);

                if ($decryptionResult === false) {
                    $message = "Error decrypting file or writing decrypted data to file.";
                } else {
                    $message = "File decrypted successfully! <a href='$outputFilePath' class='alert-link'>Download decrypted file</a>";
                }
            }
        }
    } else {
        $message = "Please provide an encryption key and a file.";
    }
}
?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Encrypt and Decrypt Files</title>
    <link href="css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="mb-4">Encrypt and Decrypt Files</h1>
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
                <form method="post" enctype="multipart/form-data">
                    <input type="hidden" name="action" value="encrypt">
                    <div class="mb-3">
                        <label for="key" class="form-label">Encryption Key:</label>
                        <input type="text" id="key" name="key" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label for="file" class="form-label">File Upload:</label>
                        <input type="file" id="file" name="file" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Encrypt</button>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                Decrypt Files
            </div>
            <div class="card-body">
                <form method="post" enctype="multipart/form-data">
                    <input type="hidden" name="action" value="decrypt">
                    <div class="mb-3">
                        <label for="key" class="form-label">Encryption Key:</label>
                        <input type="text" id="key" name="key" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label for="file" class="form-label">File Upload:</label>
                        <input type="file" id="file" name="file" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Decrypt</button>
                </form>
            </div>
        </div>
    </div>
    <script src="js/bootstrap.bundle.min.js" integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM" crossorigin="anonymous"></script>
</body>
</html>
