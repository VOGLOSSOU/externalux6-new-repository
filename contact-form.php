<?php
// Configuration de la base de données
$dsn = "mysql:host=srv1580.hstgr.io;dbname=u433704782_ExternaLux6Web";
$username = "u433704782_externaLux6";
$password = "externalux6PassWord";

try {
    // Création de la connexion PDO
    $pdo = new PDO($dsn, $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Vérification si le formulaire a été soumis
    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['submit'])) {
        // Initialisation des variables
        $name = isset($_POST['form-name']) ? htmlspecialchars(trim($_POST['form-name'])) : '';
        $email = isset($_POST['form-email']) ? htmlspecialchars(trim($_POST['form-email'])) : '';
        $company = isset($_POST['form-company']) ? htmlspecialchars(trim($_POST['form-company'])) : '';
        $subject_type = isset($_POST['form-subject']) ? htmlspecialchars(trim($_POST['form-subject'])) : '';
        $message = isset($_POST['form-message']) ? htmlspecialchars(trim($_POST['form-message'])) : '';
        
        // Création du sujet personnalisé basé sur le type sélectionné
        $subject_labels = [
            'cybersecurity-consultation' => 'Cybersecurity Consultation',
            'software-development' => 'Software Development',
            'penetration-testing' => 'Penetration Testing',
            'incident-response' => 'Incident Response',
            'security-audit' => 'Security Audit',
            'custom-solution' => 'Custom Solution',
            'partnership' => 'Partnership Opportunity',
            'other' => 'General Inquiry'
        ];
        
        $subject_label = isset($subject_labels[$subject_type]) ? $subject_labels[$subject_type] : $subject_type;
        $subject = "Contact Form - " . $subject_label;
        
        $errors = [];
        
        // Validation
        if (empty($name)) {
            $errors[] = 'Name is required.';
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Invalid email address.';
        }
        if (empty($subject_type)) {
            $errors[] = 'Subject is required.';
        }
        if (empty($message)) {
            $errors[] = 'Message is required.';
        }
        
        if (!empty($errors)) {
            $errorMessage = htmlspecialchars(implode("\\n", $errors));
            echo "<script>alert('$errorMessage'); window.history.back();</script>";
        } else {
            // Préparation du message complet avec les informations supplémentaires
            $fullMessage = "Subject: " . $subject_label . "\n";
            if (!empty($company)) {
                $fullMessage .= "Company: " . $company . "\n";
            }
            $fullMessage .= "\nMessage:\n" . $message;
            
            // Préparation de la requête SQL pour l'insertion
            $stmt = $pdo->prepare("INSERT INTO visitors_emails (name, email, subject, message) VALUES (:name, :email, :subject, :message)");
            $stmt->bindParam(':name', $name);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':subject', $subject);
            $stmt->bindParam(':message', $fullMessage);
            
            // Exécution de la requête
            if ($stmt->execute()) {
                echo "<script>alert('Thank you for contacting us! We will respond within 24 hours.'); window.location.href='contact.html';</script>";
            } else {
                error_log("Erreur lors de l'insertion dans la base de données : " . implode(", ", $stmt->errorInfo()));
                echo "<script>alert('An error occurred. Please try again.'); window.history.back();</script>";
            }
        }
    }
} catch (PDOException $e) {
    echo "<script>alert('Connection error: " . addslashes($e->getMessage()) . "'); window.history.back();</script>";
}
?>