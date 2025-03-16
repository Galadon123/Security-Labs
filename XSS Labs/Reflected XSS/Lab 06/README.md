# Reflected XSS into a JavaScript string

In this lab we will see a specific type of Cross-Site Scripting (XSS) vulnerability: **Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped**.

In this vulnerability, user input is:

1. Reflected back to the user in the page response (making it a reflected XSS)
2. Inserted directly into a JavaScript string context
3. "Protected" by escaping single quotes with backslashes
4. HTML entities are used for angle brackets and double quotes when displayed in HTML context

We will see how to exploit this vulnerability and how to prevent it.

## What is Reflected XSS?

Reflected XSS is a type of XSS attack where the malicious script is reflected off the web application back to the victim's browser. This type of XSS is common in web applications that handle user input, such as name fields, search fields, comment sections, and login forms.

![](./images/2.svg)

An attacker crafts a malicious URL containing a script and tricks a user into clicking it. The vulnerable website reflects the script in its response without proper sanitization, causing the user's browser to execute it, leading to data theft or session hijacking.

## Angle brackets and Double quotes HTML-encoded

To prevent `XSS` it is a common practice to HTML-encode the angle brackets and double quotes. Here is a example of how it is done.

```html
<script>
  var x = "<img src=1 onerror=alert(1)>";
</script>
```

If we encode the angle brackets, it will be reflected as:

```html
<script>
  var x = "&lt;img src=1 onerror=alert(1)&gt;";
</script>
```
We can also encode the double quotes, it will be reflected as:

```html
<script>
  var x = "&quot;&lt;img src=1 onerror=alert(1)&gt;&quot;";
</script>
```

Here we are encode angle brackets with `&lt;` and `&gt;` and double quotes with `&quot;`.

As we encode the angle brackets and double quotes, the script will not be executed.

## Single quotes escaped

Single quotes escaping is a common practice to prevent `XSS` attacks. Here is a example of how it is done.

### **User input from request parameter**

```javascript
const userInput = request.getParameter("search");
```
### **Attempt to Escape single quotes**
```javascript
const escapedInput = userInput.replace(/'/g, "\\'");
```
Here we are escaping the single quotes with a backslash. (e.g. `'` -> `\'`)

### **Insert into JavaScript string context**
```javascript
const vulnerableCode = `
    var searchTerm = '${escapedInput}';
    document.getElementById('results').innerHTML = 'Results for: ' + searchTerm;
`;
```
But this is not enough to prevent `XSS` attacks. An attacker can still exploit the vulnerability by injecting a specially crafted payload. Now we will see a application that is vulnerable to this type of attack.

## Hands on Lab

To demostrate that on `Poridhi's` Platform, we will deploy a application in `Docker` and then expose it with `Poridhi's` Load Balancer.

### **Step 1: Pull the Docker Image**

```bash
docker pull fazlulkarim105925/reflectedxss:v1.1
```

### **Step 2: Deploy the Application**

```bash
docker run -p 8000:8000 fazlulkarim105925/reflectedxss:v1.1
```

### **Step 3: Expose the Application**

To expose the application with `Poridhi's` Load Balancer, we need to find the `eth0` IP address of the container. To get the `eth0` IP address, we can use the following command:

```bash
ifconfig
```
![](./images/3.png)

Create a Load Balancer with the `eth0 IP` address and the port `8000`

![](./images/4.png)

### **Step 4: Access the Web Application**

Access the web application with the the provided `URL` by `loadbalancer`

![](./images/1.png)

In the search field, you can search for `Books`name or anything, as a demonstration we will not show any results but, search histroy will be reflected in the page.

You can search `Poridhi` and see the search history reflected in the page.

![](./images/2.png)

### **Step 5: Exploit the Vulnerability**

From the attackers point of view, they can exploit the vulnerability by injecting a specially crafted payload. 

They stated with injecting direct javascipt into the search field. Like this:

```javascript
<script>alert(1)</script>
```
![](./images/5.png)

From the output we can see that the payload is not executed. The payload is rejected by the application. Which confirms that the application handling `script` tag properly.


Now try payload without angle brackets

```javascript
\'; alert(1); //
```

![](./images/6.png)

From the output we can see that the payload is executed. In this Payload

- 1. The ' (single quote) closes the existing string in







1. Uses backslash escaping to break out of the JavaScript string
2. Injects arbitrary JavaScript code
3. Uses comment syntax to maintain valid JavaScript

A classic payload for this vulnerability is:

```javascript
\'; alert(document.domain); //
```

### Exploitation Analysis

When this payload is processed by the vulnerable application:

1. The application escapes the single quote: `\\\'`
2. In JavaScript, `\\\'` is interpreted as:
   - `\\` → a literal backslash character
   - `\'` → a literal single quote
3. This effectively terminates the string
4. The subsequent code `; alert(document.domain);` executes as JavaScript
5. The `//` comments out the remainder of the line to prevent syntax errors

### Common Misconceptions and Failed Protections

1. **Escaping single quotes is insufficient**: Merely replacing `'` with `\'` doesn't prevent XSS when backslashes themselves aren't properly handled.

2. **HTML encoding doesn't protect JavaScript contexts**: Even if `<` becomes `&lt;` in HTML, when inserted into JavaScript, it's interpreted in the JavaScript context, not the HTML context.

3. **JavaScript string context requires specialized encoding**: Each context (HTML, JavaScript, CSS, URL) requires its own encoding strategy.


## Conclusion
In this lab we have seen a specific type of `XSS` vulnerability: **Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped**.



<!-- ### Proof of Concept Exploit

The following search term successfully exploits the vulnerability:

```
\'; alert(1); //
```

When this payload is entered in the search field and processed:

1. The application applies single quote escaping: `\\\'`
2. This allows breaking out of the JavaScript string context
3. The `alert(1)` code executes
4. The comment `//` ensures valid JavaScript syntax

## Impact

Successful exploitation of this vulnerability could allow attackers to:

1. Execute arbitrary JavaScript in the context of the victim's browser
2. Access sensitive user information (cookies, session tokens)
3. Perform actions on behalf of the victim user
4. Redirect users to phishing sites
5. Deface the website content

## Real-World Examples

This vulnerability has been found in many applications:

1. Search functionality in e-commerce platforms
2. Analytics dashboards that display user-provided parameters
3. Content management systems that render user inputs in JavaScript contexts
4. Reporting tools that generate dynamic JavaScript based on user queries

## Proper Remediation Strategies

### 1. Context-Appropriate Encoding

Use a proper JavaScript string encoder that handles all special characters:

```javascript
function encodeJsString(input) {
  return input
    .replace(/\\/g, "\\\\") // Escape backslashes first
    .replace(/'/g, "\\'") // Escape single quotes
    .replace(/"/g, '\\"') // Escape double quotes
    .replace(/\n/g, "\\n") // Escape newlines
    .replace(/\r/g, "\\r") // Escape carriage returns
    .replace(/\t/g, "\\t") // Escape tabs
    .replace(/\f/g, "\\f") // Escape form feeds
    .replace(/\b/g, "\\b") // Escape backspace
    .replace(/\v/g, "\\v"); // Escape vertical tab
}
```

### 2. Use JSON.stringify() for JavaScript String Encoding

Modern JavaScript provides a built-in way to safely encode strings:

```javascript
const safeValue = JSON.stringify(userInput);
// then use without the surrounding quotes:
const js = `var x = ${safeValue};`; // x will be properly string-encoded
```

### 3. Avoid Direct DOM Construction with User Input

Instead of constructing HTML with user input, prefer safer DOM manipulation:

```javascript
const textNode = document.createTextNode(userInput);
resultElement.appendChild(textNode);
```

### 4. Use Content Security Policy (CSP)

Implement a strict CSP to mitigate the impact of XSS:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```

### 5. Use Modern Frameworks

Modern JavaScript frameworks like React, Vue, and Angular automatically escape variables in templates, reducing the risk of XSS.

## Testing for This Vulnerability

To test for this vulnerability:

1. Identify inputs that are reflected in JavaScript string contexts
2. Try payloads that attempt to break out of the string:
   - `\'; alert(1); //`
   - `\\'; alert(1); //`
   - `'; alert(1); //`
3. Check if JavaScript executes without being treated as string content

## Conclusion

Reflected XSS in JavaScript string contexts remains common despite being well-documented. The key insight is that different contexts (HTML, JavaScript, CSS, URL) require different encoding strategies. Simply escaping quotes is insufficient when the input is placed inside a JavaScript string context.

Application developers must implement context-sensitive output encoding and follow defense-in-depth principles to effectively protect against this class of vulnerabilities.

## References -->
