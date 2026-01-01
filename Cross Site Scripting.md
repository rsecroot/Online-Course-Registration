
**BUG Author: [Ravi Sharma]**

**Product Information:**

- Vendor Homepage: (https://phpgurukul.com/online-course-registration-free-download/)
- Affected Version: [<= v3.1]
- BUG Author: Ravi Sharma

**Vulnerability Details**

- Type: Stored Cross-Site Scripting via File Upload in PHP Gurukul Online Course Registration System
- Affected URL: http://localhost/onlinecourse/my-profile.php, http://localhost//onlinecourse/admin/edit-student-profile.php
- Vulnerable Parameter:  /onlinecourse/my-profile.php, /onlinecourse/admin/edit-student-profile.php - Student Photo 

**Vulnerable Files:**

- File Name: /onlinecourse/
- Path: /onlinecourse/my-profile.php, /onlinecourse/admin/edit-student-profile.php

**Vulnerability Type**

- Stored Cross-Site Scripting CWE: CWE-79, CWE-434, CWE-80
- Severity Level: 8.7 (HIGH) - Potentially 9.0+ depending on implementation

**Root Cause:**

The application accepts file uploads without validating file types or content, allowing malicious SVG/HTML files containing JavaScript to be uploaded and stored. When administrators view student profiles, these files are rendered in their browsers, executing the embedded JavaScript in the administrator's security context.

**No Content Sanitization:**

- SVG files with embedded <script> tags accepted
- HTML files with JavaScript accepted
- No inspection or filtering of file contents
- Dangerous tags not removed or escaped

1. NO FILE TYPE VALIDATION - Student Upload (my-profile.php) - Line 13: (/onlinecourse/my-profile.php)

_**$photo=$_FILES["photo"]["name"];
move_uploaded_file($_FILES["photo"]["tmp_name"],"studentphoto/".$_FILES["photo"]["name"]);**___

2. Admin Upload (edit-student-profile.php) - Line 15: (/onlinecourse/admin/edit-student-profile.php)
**_$photo=$_FILES["photo"]["name"];
move_uploaded_file($_FILES["photo"]["tmp_name"],"studentphoto/".$_FILES["photo"]["name"]);_**

**Impact:**

An attacker can upload a malicious SVG or HTML file containing JavaScript code. When the file is accessed (e.g., when viewing student profile or student list), the XSS payload executes, potentially stealing session cookies, performing actions on behalf of the victim, or redirecting to phishing pages.

If an administrator views a student profile containing the malicious file, the attacker can steal the admin session and gain complete control of the application.

**Vulnerability Details:**
-------------------------------------------------------------------------------------------------------------------------------------

**Description:**

A critical stored cross-site scripting (XSS) vulnerability exists in PHP Gurukul Online Course Registration System v3.1 that allows students to upload malicious files which execute JavaScript code when administrators view or edit student profiles.

The vulnerability is located in the student registration photo upload functionality. The application fails to properly validate uploaded file types and does not sanitize file content, allowing malicious SVG or HTML files to be uploaded and stored. When an administrator accesses the student management interface and views or edits a student profile (/admin/edit-student-profile.php), the malicious file is rendered, causing the embedded JavaScript to execute in the administrator's browser context.

$photo=$_FILES["photo"]["name"];
move_uploaded_file($_FILES["photo"]["tmp_name"],"studentphoto/".$_FILES["photo"]["name"]);

This vulnerability is particularly critical because:
- It affects privileged administrator accounts
- Requires only low-privilege student access to exploit
- Executes in a trusted administrative context
- Can lead to complete system compromise
- Administrator only needs to view student list (common administrative task)

**Vulnerable Code Example:**

/onlinecourse/admin/edit-student-profile.php
<img width="762" height="85" alt="Screenshot 2026-01-01 at 10 57 44" src="https://github.com/user-attachments/assets/4f89fcca-2a6d-461d-be11-f39868f75ec7" />

/onlinecourse/my-profile.php
<img width="823" height="75" alt="Screenshot 2026-01-01 at 10 57 31" src="https://github.com/user-attachments/assets/6dec2af8-0212-44db-9df0-a9ba6c99e5dd" />


**Step-by-Step Reproduction:**
### **Trigger XSS as Student**

1. Login as student
2. Navigate to: /onlinecourse/my-profile.php
3. Click "Browse..." under "Upload New Photo"
4. Select: malicious.svg
5. Click "Update"
6. File uploaded to: /studentphoto/malicious.svg and triggerd as XSS attack.

**Screenshots**
[Attach screenshots showing:]

<img width="1392" height="1212" alt="Screenshot 2025-12-31 at 12 33 19" src="https://github.com/user-attachments/assets/1e56bead-a88e-4c71-b89f-c8537a8e5de0" />

<img width="1173" height="862" alt="Screenshot 2025-12-31 at 12 33 53" src="https://github.com/user-attachments/assets/69f146f0-3dd5-4232-b149-1c1e8ec3862f" />

### **Trigger XSS as Admin**

1. Login as administrator
2. Navigate to: MANAGE STUDENTS tab
3. Click "Edit" on student with malicious upload
4. URL: /admin/edit-student-profile.php?id=10806121
5. Page loads malicious SVG in <img> tag
6. XSS executes: Alert shows XSS attack

**Screenshots**
[Attach screenshots showing:]

<img width="1421" height="1160" alt="Screenshot 2026-01-01 at 11 24 18" src="https://github.com/user-attachments/assets/23b75f25-1c82-4503-9fbd-5c14e93dacfc" />

<img width="1527" height="1023" alt="Screenshot 2026-01-01 at 11 19 26" src="https://github.com/user-attachments/assets/247462b3-4717-4a75-b9c8-44e98ebe5162" />

**Impact Assessment:**

The XSS executes with administrator privileges, allowing an attacker to:
- Steal administrator session tokens and cookies
- Perform actions as the administrator
- Create new administrator accounts
- Modify system configuration
- Access all student data

**Affected Components:**

- File Upload Handler - Student Profile
- File Upload Handler - Admin Edit Student
- File Rendering - Student Profile Page
- File Rendering - Admin Edit Page (XSS TRIGGER POINT)

**Remediation Recommendations:**

**Immediate Fix**

1. Disallow Dangerous File Types
- Block uploads of executable formats such as:.svg, .html, .htm, .xml
- Use a strict allowlist (e.g., .jpg, .png, .pdf).

2. Enforce Proper Content-Type Handling
- Validate file content using server-side MIME type checks.
- Do not rely solely on client-provided Content-Type headers.

3. Sanitize SVG Files (If SVG Is Required)
- Remove <script>, event handlers (onload, onclick), and external references.
- Use a trusted SVG sanitization library.

4. Serve Uploaded Files Safely
- Serve uploads from a separate domain (e.g., uploads.example-cdn.com).
- Apply the following HTTP headers:
Content-Disposition: attachment
Content-Type: application/octet-stream
X-Content-Type-Options: nosniff

5. Implement Content Security Policy (CSP)
- Use a restrictive CSP to limit script execution: Content-Security-Policy: default-src 'none'; img-src 'self'

6. Disable Inline JavaScript Execution
- Avoid rendering user-uploaded content directly within application pages.

7. Conduct security code review

**Secure Code Example**
```php
<?php
if(isset($_POST['submit']))
{
    $studentname = mysqli_real_escape_string($con, $_POST['studentname']);
    $cgpa = mysqli_real_escape_string($con, $_POST['cgpa']);
    
    // SECURE FILE UPLOAD HANDLING
    if(isset($_FILES["photo"]) && $_FILES["photo"]["error"] == UPLOAD_ERR_OK) {
        
        // 1. VALIDATE FILE SIZE
        $max_file_size = 2 * 1024 * 1024; // 2MB
        if($_FILES["photo"]["size"] > $max_file_size) {
            echo '<script>alert("File too large. Maximum size: 2MB")</script>';
            exit();
        }
        
        // 2. WHITELIST ALLOWED EXTENSIONS
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
        $file_extension = strtolower(pathinfo($_FILES["photo"]["name"], PATHINFO_EXTENSION));
        
        if(!in_array($file_extension, $allowed_extensions)) {
            echo '<script>alert("Invalid file type. Only JPG, PNG, GIF allowed.")</script>';
            exit();
        }
        
        // 3. VALIDATE MIME TYPE (Check actual file content)
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $detected_mime = finfo_file($finfo, $_FILES["photo"]["tmp_name"]);
        finfo_close($finfo);
        
        $allowed_mimes = [
            'image/jpeg',
            'image/jpg', 
            'image/png',
            'image/gif'
        ];
        
        if(!in_array($detected_mime, $allowed_mimes)) {
            echo '<script>alert("Invalid file content. File is not a valid image.")</script>';
            exit();
        }
        
        // 4. VERIFY IMAGE INTEGRITY
        $image_info = getimagesize($_FILES["photo"]["tmp_name"]);
        if($image_info === false) {
            echo '<script>alert("File is not a valid image.")</script>';
            exit();
        }
        
        // 5. GENERATE SECURE FILENAME (Prevent path traversal & predictability)
        $unique_id = uniqid('student_', true);
        $secure_filename = $unique_id . '.' . $file_extension;
        
        // 6. DEFINE SECURE UPLOAD PATH (Outside web root ideally)
        $upload_directory = "studentphoto/";
        $upload_path = $upload_directory . $secure_filename;
        
        // 7. MOVE FILE SECURELY
        if(move_uploaded_file($_FILES["photo"]["tmp_name"], $upload_path)) {
            
            // 8. ADDITIONAL SECURITY: Re-encode image to strip metadata/malicious content
            switch($detected_mime) {
                case 'image/jpeg':
                case 'image/jpg':
                    $image = imagecreatefromjpeg($upload_path);
                    imagejpeg($image, $upload_path, 90);
                    break;
                case 'image/png':
                    $image = imagecreatefrompng($upload_path);
                    imagepng($image, $upload_path, 9);
                    break;
                case 'image/gif':
                    $image = imagecreatefromgif($upload_path);
                    imagegif($image, $upload_path);
                    break;
            }
            imagedestroy($image);
            
            // 9. DELETE OLD PHOTO if exists
            $old_photo_query = mysqli_query($con, "SELECT studentPhoto FROM students 
                                                   WHERE StudentRegno='".$_SESSION['login']."'");
            $old_photo_row = mysqli_fetch_array($old_photo_query);
            if($old_photo_row['studentPhoto'] != "" && 
               file_exists($upload_directory . $old_photo_row['studentPhoto'])) {
                unlink($upload_directory . $old_photo_row['studentPhoto']);
            }
            
            // 10. STORE FILENAME IN DATABASE (Use prepared statement)
            $stmt = $con->prepare("UPDATE students SET studentName=?, studentPhoto=?, cgpa=? 
                                   WHERE StudentRegno=?");
            $stmt->bind_param("ssds", $studentname, $secure_filename, $cgpa, $_SESSION['login']);
            
            if($stmt->execute()) {
                echo '<script>alert("Student Record updated Successfully!")</script>';
                echo '<script>window.location.href="my-profile.php"</script>';
            } else {
                // Rollback: delete uploaded file if DB update fails
                unlink($upload_path);
                echo '<script>alert("Database error. Please try again.")</script>';
            }
            $stmt->close();
            
        } else {
            echo '<script>alert("File upload failed. Please try again.")</script>';
        }
        
    } else {
        // No file uploaded, update other fields only
        $stmt = $con->prepare("UPDATE students SET studentName=?, cgpa=? 
                              WHERE StudentRegno=?");
        $stmt->bind_param("sds", $studentname, $cgpa, $_SESSION['login']);
        
        if($stmt->execute()) {
            echo '<script>alert("Student Record updated Successfully!")</script>';
            echo '<script>window.location.href="my-profile.php"</script>';
        }
        $stmt->close();
    }
}
?>

**References**

- OWASP Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- CWE-284: https://cwe.mitre.org/data/definitions/79.html
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- CWE-80: https://cwe.mitre.org/data/definitions/80.html
