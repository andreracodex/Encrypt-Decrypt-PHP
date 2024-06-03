<?php

session_start();
include 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}


?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Disk Crypt</title>
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">
    <link href="css/styledash.css" rel="stylesheet">
</head>

<body>
    <div class="wrapper">
        <!-- Sidebar -->
        <?php include 'sidebar.php' ?>

        <!-- Page Content -->
        <div id="content">
            <div class="container mt-5">
                <h1 class="mb-4">Welcome To Disk Crypt</h1>
                <hr>
                <h2>Elliptic Curve Cryptography (ECC)</h2>
                <p>
                    ECC adalah teknik enkripsi kunci publik yang modern dan terkenal karena ukurannya yang lebih kecil, kecepatannya yang lebih tinggi, dan efisiensinya dibandingkan dengan metode kriptografi lainnya. Mari kita bahas lebih lanjut:
                </p>

                <h2>Struktur Kurva Elips</h2>
                <p>
                    ECC berdasarkan struktur aljabar dari kurva elips di atas bidang terbatas. Kurva elips ini memungkinkan penggunaan kunci lebih kecil untuk mencapai tingkat keamanan yang setara dengan sistem kriptografi lain yang menggunakan eksponensiasi modular di bidang Galois, seperti RSA dan ElGamal.
                </p>

                <h2>Penggunaan ECC</h2>
                <p>
                    ECC digunakan untuk berbagai fungsi kriptografi, termasuk:
                </p>
                <ul>
                    <li>Key agreement: ECC memungkinkan dua pihak untuk setuju pada kunci bersama tanpa mengungkapkan kunci sebenarnya.</li>
                    <li>Digital signatures: ECC digunakan untuk menghasilkan tanda tangan digital yang otentik dan aman.</li>
                    <li>Pseudo-random generators: ECC dapat menghasilkan deret angka acak yang berguna dalam kriptografi.</li>
                    <li>Enkripsi: Meskipun ECC tidak secara langsung digunakan untuk enkripsi, namun bisa dikombinasikan dengan skema enkripsi simetris untuk tujuan ini.</li>
                </ul>

                <h2>Sejarah</h2>
                <p>
                    Penggunaan kurva elips dalam kriptografi diusulkan secara independen oleh Neal Koblitz dan Victor S. Miller pada tahun 1985. Algoritma ECC mulai digunakan secara luas pada tahun 2004 hingga 2005. NIST merekomendasikan lima belas kurva elips pada tahun 1999, termasuk kurva-kurva dengan bidang terbatas dan biner. NSA mengumumkan Suite B pada RSA Conference 2005, yang secara eksklusif menggunakan ECC untuk pembuatan tanda tangan digital dan pertukaran kunci. ECC digunakan dalam protokol populer seperti Transport Layer Security (TLS) dan Bitcoin.
                </p>
                <hr>
                <h2>Advanced Encryption Standard (AES)</h2>
                <p>
                    Advanced Encryption Standard (AES), juga dikenal dengan nama Rijndael, adalah algoritma enkripsi blok simetris yang telah menjadi standar industri untuk kriptografi kunci simetris. Pada tahun 2001, AES dipilih oleh National Institute of Standards and Technology (NIST) Amerika Serikat sebagai pengganti Data Encryption Standard (DES) yang lebih tua.
                </p>

                <h2>Struktur dan Operasi</h2>
                <p>
                    AES beroperasi dengan ukuran blok 128 bit dan menggunakan kunci simetris dengan panjang 128, 160, 192, 224, atau 256 bit. Algoritma ini bekerja pada blok data dengan menggantikan dan mempermutasi byte-byte data. AES menggunakan substitusi S-box dan transformasi ShiftRows, serta MixColumns untuk mengacak data.
                </p>

                <h2>Keamanan dan Efisiensi</h2>
                <p>
                    AES dianggap sebagai salah satu protokol enkripsi terbaik karena menggabungkan kecepatan dan keamanan dengan baik. Algoritma ini telah digunakan secara luas dalam berbagai aplikasi, termasuk keamanan nirkabel dan komputasi awan.
                </p>

                <h2>Penggunaan</h2>
                <p>
                    AES digunakan dalam berbagai protokol dan aplikasi, termasuk Transport Layer Security (TLS) untuk mengamankan komunikasi web dan diskusi Bitcoin. Keberhasilan AES terletak pada desainnya yang kuat dan efisien.
                </p>
                <?php if (isset($_SESSION['message'])) : ?>
                    <div class="label <?php echo $_SESSION['message_type'] === 'success' ? 'success' : 'eror'; ?>" role="alert">
                        <?= $_SESSION['message'] ?>
                    </div>
                    <?php unset($_SESSION['message']); ?>
                    <?php unset($_SESSION['message_type']); ?>
                <?php endif; ?>
                <!-- Your existing forms for encryption and decryption... -->
            </div>
        </div>
    </div>
    <script src="js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.10.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>

</html>