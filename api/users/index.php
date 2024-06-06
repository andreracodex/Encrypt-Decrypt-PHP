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

// Function to generate a token
function generateToken() {
    return bin2hex(random_bytes(16));
}

// Function to register a user
function registerUser($username, $password, $email, $conn) {
    // Check if the username already exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        return ['success' => false, 'message' => 'Username already exists.'];
    } else {
        $stmt->close();
        
        // Hash the password and generate a token
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        $token = generateToken();

        // Insert the new user into the database
        $stmt = $conn->prepare("INSERT INTO users (username, password, token, email) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $username, $hashedPassword, $token, $email);

        if ($stmt->execute()) {
            return ['success' => true, 'message' => 'User registered successfully.'];
        } else {
            return ['success' => false, 'message' => 'Registration failed.'];
        }
    }
}

// Function to login a user
function loginUser($username, $password, $conn) {
    $username = $conn->real_escape_string($username);
        
    $sql = "SELECT * FROM users WHERE username='$username'";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            $id = $user["id"];
            $token = generateToken();;
            
            $lol = "UPDATE users SET token = '$token' WHERE id = '$id'";
            $lolhasil = $conn->query($lol);
            if($lolhasil == true) {
                return ['success' => true, 
                        'message' => 'Login successfully.',
                        'token' => $token,
                    ];
            }else{
                return ['success' => false, 
                        'message' => 'Login Failed.'
                    ];    
            }
        } else {
            return ['success' => false, 'message' => 'Password verification failed'];
        }
    } else {
        return ['success' => false, 'message' => 'User not found, please register'];
    }
}


// Function to logout a user
function logoutUser($token, $conn) {
    $stmt = $conn->prepare("UPDATE users SET token = NULL WHERE token = ?");
    $stmt->bind_param("s", $token);

    if ($stmt->execute()) {
        return ['success' => true, 'message' => 'Logout successful.'];
    } else {
        return ['success' => false, 'message' => 'Invalid token.'];
    }
}

// Function to validate Bearer token
function validateBearerToken($token, $conn) {
    $stmt = $conn->prepare("SELECT id FROM users WHERE token = ?");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $stmt->store_result();

    return $stmt->num_rows > 0;
}

// Handle incoming API requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'register') {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $email = $_POST['email'] ?? '';

        if (empty($username) || empty($password)) {
            echo json_encode(['success' => false, 'message' => 'Username and password are required.']);
            exit;
        }

        $result = registerUser($username, $password, $email, $conn);
        echo json_encode($result);
    } elseif ($action === 'login') {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';

        if (empty($username) || empty($password)) {
            echo json_encode(['success' => false, 'message' => 'Username and password are required.']);
            exit;
        }

        $result = loginUser($username, $password, $conn);
        echo json_encode($result);
    } elseif ($action === 'logout') {
        $headers = apache_request_headers();
        $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';

        if (strpos($authHeader, 'Bearer ') === 0) {
            $token = substr($authHeader, 7);
            $result = logoutUser($token, $conn);
            echo json_encode($result);
        } else {
            echo json_encode(['success' => false, 'message' => 'Authorization header is missing or invalid.']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid action.']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
}

// Close database connection
$conn->close();
?>
