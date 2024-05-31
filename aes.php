<?php
// Function to encrypt the file
function encryptFile($filePath, $key) {
    $iv = random_bytes(16); // AES-128-CTR uses a 16-byte IV
    $fileContents = file_get_contents($filePath);
    $encryptedData = openssl_encrypt($fileContents, 'AES-128-CTR', $key, 0, $iv);
    return base64_encode($iv . $encryptedData); // Store the IV with the encrypted data
}

// Function to decrypt the file
function decryptFile($encryptedData, $key) {
    $data = base64_decode($encryptedData);
    $iv = substr($data, 0, 16);
    $encryptedText = substr($data, 16);
    return openssl_decrypt($encryptedText, 'AES-128-CTR', $key, 0, $iv);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $key = $_POST['key'];
    $file = $_FILES['file'];

    if ($key && $file) {
        $filePath = $file['tmp_name'];
        $action = $_POST['action'];

        if ($action === 'encrypt') {
            $encryptedData = encryptFile($filePath, $key);
            file_put_contents('encrypted_file.txt', $encryptedData);
            $message = "File encrypted successfully! <a href='encrypted_file.txt' class='alert-link'>Download encrypted file</a>";
        } elseif ($action === 'decrypt') {
            $encryptedData = file_get_contents($filePath);
            $decryptedData = decryptFile($encryptedData, $key);
            file_put_contents('decrypted_file.txt', $decryptedData);
            $message = "File decrypted successfully! <a href='decrypted_file.txt' class='alert-link'>Download decrypted file</a>";
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
    <title>Encrypt and Decrypt Files (AES)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
</head>
<body>
    <div class="container mt-5">
        <h1 class="mb-4">Encrypt and Decrypt Files (AES)</h1>
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
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM" crossorigin="anonymous"></script>
</body>
</html>
