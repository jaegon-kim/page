<html>
<head>

<script language="JavaScript">

function checkInput(form)
{
//	alert(form.in_str_name.value);
	return (true);
}
</script>

</head>
<body>

<form method ="post" action="db_write.php" 
		onSubmit="return checkInput(this)">
    <table width=70% align=center>
	<tr>
	   <td colspan=3>&nbsp;</td>
	</tr>
	  <tr bgcolor=#d9d9f3>
	  <td align=center><b>이름</b></td>
	  <td align=center><b>내용</b></td>
	</tr>
	<tr>
	  <td>
	     <input type = "text" name = in_str_name size=10>
	  </td>
	  <td>
	     <input type = "text" name = in_str_contents size=80>
	  </td>
	</tr>
    	<tr>
	  <td colspan=3 align=right>
	     <input type="submit" value="등록" >
             <input type="reset" value="취소" >
	  </td>
	</tr>
    </table>

</form>


<?php

?>
</body>
</html>


