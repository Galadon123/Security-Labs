# Insecure Direct Object Reference (IDOR)

Insecure Direct Object Reference (IDOR) is a critical security vulnerability that occurs when an application exposes a reference to an internal implementation object, such as a file, directory, database record, or key. Attackers can manipulate these references to access unauthorized data or perform unauthorized actions, bypassing access control mechanisms.

## **Objective**

- Running the vulnerable `Application` in `Docker`
- Performing an `IDOR` attack on the `Application`
- Understanding how attackers can manipulate object references to access unauthorized data
- Identifying ways to detect and mitigate IDOR vulnerabilities
- Demonstrating security best practices to prevent IDOR attacks in production systems

## **What is Insecure Direct Object Reference (IDOR)?**

IDOR is a **web security vulnerability** that occurs when an application uses user-supplied input to access objects directly without sufficient authorization checks. This allows attackers to bypass authorization and access resources they shouldn't have permission to access, such as private user data, administrative functions, or internal system files.

![IDOR Vulnerability Diagram](assets/idor.drawio.svg)

## **How Does IDOR Work?**

### **1. Identification**  
The attacker identifies a parameter or URL that references an object, such as a user account, message, or file. This could be in the form of a numeric ID, UUID, or other unique identifier.

- Example parameter in URL:  
  ```
  https://example.com/messages/123
  ```
  Where `123` is the identifier for a message.

### **2. Manipulation**  
The attacker modifies the reference to point to a different object that they should not have access to. For instance, changing the message ID from 123 to 124 to access someone else's message.

- Example manipulated URL:  
  ```
  https://example.com/messages/124
  ```

### **3. Access**  
If the application does not properly verify that the user has the right to access the referenced object, the attacker gains unauthorized access to the data or functionality.

## **Types of IDOR Vulnerabilities**

![IDOR Types]
*(Suggested image: A flowchart or table showing different types of IDOR vulnerabilities)*

### **1. Direct Reference to Private Resources**  
The application directly exposes sensitive resources through identifiers in URLs, form fields, or API endpoints without proper authorization checks.

### **2. Predictable Resource Location**  
Resources are stored or accessed using predictable patterns that allow attackers to guess valid identifiers.

### **3. Insecure Access Control for Functions**  
The application allows access to sensitive functions without verifying the user's permissions to perform those actions.

### **4. Reference Maps**  
The application uses client-side maps or caches that can be manipulated to reference unauthorized objects.

## **Impact of IDOR Vulnerabilities**

- **Data Breach:** Unauthorized access to other users' private information
- **Account Takeover:** Ability to modify account details of other users
- **Privilege Escalation:** Performing actions reserved for higher privilege users
- **Data Manipulation:** Modifying or deleting data belonging to other users
- **Business Logic Bypass:** Circumventing business rules and restrictions

## **Hands-on with IDOR**

1. **Pull the Docker Image**

   ```bash
   docker pull yourusername/idor-lab:latest
   ```

2. **Run the Docker Container**

   ```bash
   docker run -d -p 5000:5000 yourusername/idor-lab:latest
   ```

3. **Create a Load Balancer in Poridhi's Cloud**

   Find the `eth0` IP address with `ifconfig` command.

   ![ifconfig output]
   *(Suggested image: Screenshot showing the result of the ifconfig command with eth0 IP highlighted)*

   Create a Load Balancer with the `eth0 IP` address and the port `5000`

   ![Load Balancer Creation]
   *(Suggested image: Screenshot of load balancer configuration page)*
   
4. **Access the Web Application**

   Access the web application with the URL provided by the `loadbalancer`

   ![Application Login Page]
   *(Suggested image: Screenshot of the application's login page)*
   
### **Exploring the Application**

This web app is designed to demonstrate IDOR vulnerabilities. It allows users to register, login, post messages, and manage their profiles. The application uses direct object references in URLs and API endpoints without proper authorization checks, making it vulnerable to IDOR attacks.

1. Register two user accounts: "User1" and "User2"
2. Login as "User1" and create a message
3. Note how the application uses numeric IDs in the URLs and for referencing resources

![User Dashboard]
*(Suggested image: Screenshot of the user dashboard showing the message list)*

### **Setting Up BurpSuite for Traffic Interception**

BurpSuite is a powerful web application security testing tool that allows you to intercept and modify HTTP/HTTPS traffic between your browser and the application server.

1. **Configure Browser to Use BurpSuite Proxy**
   - Set up your browser to use the proxy at `127.0.0.1:8080`
   
   ![Browser Proxy Settings]
   *(Suggested image: Screenshot of browser proxy configuration)*

2. **Start BurpSuite and Configure the Proxy**
   - Open BurpSuite and go to the Proxy tab
   - Ensure Intercept is on
   
   ![BurpSuite Proxy Setup]
   *(Suggested image: Screenshot of BurpSuite proxy tab with intercept enabled)*

3. **Install BurpSuite CA Certificate**
   - Navigate to http://burp to download and install the Burp CA certificate in your browser
   
   ![BurpSuite Certificate Installation]
   *(Suggested image: Screenshot showing the certificate installation process)*

### **Exploiting the IDOR Vulnerability**

#### **1. Message Deletion IDOR**

Let's exploit the IDOR vulnerability in the message deletion functionality:

1. Login as "User1" and create a message
2. Note the message ID in the URL when viewing the message
3. Login as "User2" and create another message
4. With BurpSuite running, try to delete "User1"'s message as "User2"

**Step 1:** Click the delete button for your own message and capture the request in BurpSuite

![BurpSuite Request Capture]
*(Suggested image: Screenshot of BurpSuite showing the intercepted delete request)*

**Step 2:** Observe the request structure:
```
GET /delete_message/2 HTTP/1.1
Host: example.com
Cookie: session=abc123...
```

**Step 3:** Modify the message ID to target "User1"'s message:
```
GET /delete_message/1 HTTP/1.1
Host: example.com
Cookie: session=abc123...
```

**Step 4:** Forward the modified request and observe that you can delete another user's message without proper authorization!

![Successful IDOR Exploitation]
*(Suggested image: Screenshot showing successful deletion of another user's message)*

#### **2. Account Deletion IDOR**

The application also has an IDOR vulnerability in the account deletion functionality:

1. Login as "User2"
2. Navigate to the profile page
3. With BurpSuite running, initiate an account deletion request for your own account
4. Modify the request to target "User1"'s account

**Step 1:** Click "Delete Account" and capture the request in BurpSuite:
```
POST /delete_account HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=xyz789...
X-User-ID: 2
```

**Step 2:** Modify the X-User-ID header to target "User1":
```
POST /delete_account HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=xyz789...
X-User-ID: 1
```

**Step 3:** Forward the modified request and observe that you can delete another user's account!

![Account Deletion IDOR]
*(Suggested image: Screenshot showing successful deletion of another user's account)*

## **How to Prevent IDOR Vulnerabilities**

### 1. Implement Proper Access Control Checks
**Protection Mechanism:** Verify user authorization for every object access request.

**How it protects:** By checking if the current user has permission to access the requested resource before providing it, even if they have the correct reference.

**Implementation (Python with Flask):**
```python
@app.route('/delete_message/<int:message_id>')
def delete_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get the message
    message = Message.query.get_or_404(message_id)
    
    # Check if the current user owns the message
    if message.user_id != session['user_id']:
        flash('You are not authorized to delete this message')
        return redirect(url_for('home'))
    
    # Delete the message
    db.session.delete(message)
    db.session.commit()
    
    flash('Message deleted!')
    return redirect(url_for('home'))
```

### 2. Use Indirect Object References
**Protection Mechanism:** Use temporary or indirect references that are mapped to the actual database identifiers server-side.

**How it protects:** By hiding the actual structure of your data and making it difficult for attackers to guess or manipulate references.

**Implementation (Python):**
```python
import uuid

# Generate indirect references
@app.route('/messages')
def list_messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Retrieve user's messages
    user_messages = Message.query.filter_by(user_id=session['user_id']).all()
    
    # Create temporary reference map for this session
    reference_map = {}
    for message in user_messages:
        temp_id = str(uuid.uuid4())
        reference_map[temp_id] = message.id
    
    # Store map in session
    session['reference_map'] = reference_map
    
    return render_template('messages.html', messages=user_messages, ref_map=reference_map)

# Use indirect references for deletion
@app.route('/delete_message/<string:temp_id>')
def delete_message(temp_id):
    if 'user_id' not in session or 'reference_map' not in session:
        return redirect(url_for('login'))
    
    # Check if the temp_id exists in the reference map
    if temp_id not in session['reference_map']:
        flash('Invalid message reference')
        return redirect(url_for('list_messages'))
    
    # Get the actual message ID
    message_id = session['reference_map'][temp_id]
    
    # Delete the message (with ownership check for defense in depth)
    message = Message.query.get_or_404(message_id)
    if message.user_id != session['user_id']:
        flash('You are not authorized to delete this message')
        return redirect(url_for('list_messages'))
    
    db.session.delete(message)
    db.session.commit()
    
    # Remove from reference map
    session['reference_map'].pop(temp_id, None)
    
    flash('Message deleted!')
    return redirect(url_for('list_messages'))
```

### 3. Implement a Role-Based Access Control (RBAC) System
**Protection Mechanism:** Define roles with specific permissions and assign users to these roles.

**How it protects:** By creating a structured approach to access control that ensures users can only access resources appropriate for their role.

**Implementation Example:**
```python
def has_permission(user_id, resource_id, action):
    # Get user's role
    user = User.query.get(user_id)
    user_role = Role.query.get(user.role_id)
    
    # Check if the role has permission for this action on this resource
    permission = Permission.query.filter_by(
        role_id=user_role.id,
        resource_type=resource_id.__class__.__name__,
        action=action
    ).first()
    
    return permission is not None

# Usage in route
@app.route('/delete_message/<int:message_id>')
def delete_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    message = Message.query.get_or_404(message_id)
    
    # Check if user owns the message OR has admin permission
    if message.user_id == session['user_id'] or has_permission(session['user_id'], message, 'delete'):
        db.session.delete(message)
        db.session.commit()
        flash('Message deleted!')
    else:
        flash('You are not authorized to delete this message')
    
    return redirect(url_for('home'))
```

### 4. Use Per-Request CSRF Tokens
**Protection Mechanism:** Require unique tokens for each action that changes state.

**How it protects:** By preventing cross-site request forgery attacks that could be used alongside IDOR vulnerabilities.

**Implementation (Flask with Flask-WTF):**
```python
from flask_wtf.csrf import CSRFProtect

# Setup CSRF protection
csrf = CSRFProtect(app)

# In your template
```html
<form method="post" action="{{ url_for('delete_message', message_id=message.id) }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <button type="submit">Delete</button>
</form>
```

### 5. Implement API Rate Limiting
**Protection Mechanism:** Limit the number of requests a user can make in a given time period.

**How it protects:** By making it more difficult for attackers to enumerate or brute force object references.

**Implementation (Flask with Flask-Limiter):**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/delete_message/<int:message_id>')
@limiter.limit("10 per minute")
def delete_message(message_id):
    # Implementation here
```

## **Conclusion**

In this lab, we explored Insecure Direct Object Reference (IDOR) vulnerabilities and their impact on web applications. We demonstrated how attackers can manipulate object references to access unauthorized data and perform unauthorized actions. By implementing proper access control checks, using indirect references, implementing RBAC systems, using CSRF tokens, and implementing rate limiting, we can effectively prevent IDOR vulnerabilities in our web applications.

These security measures are essential for protecting user data and maintaining the integrity of web services in production environments. Remember that security is a layered approach - implementing multiple protections provides defense in depth against potential attackers.