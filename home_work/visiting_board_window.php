<html>
<head>
<?PHP
	
	//현재 file data 의 최고 index를 찾아 냄 
	function find_max_index($arr)
	{
		$max_index=1;
		//연관 배열의 키 값을 이용하여 파일 데이터 베이스의 키로 
		//사용하며 형식은 "<번호 >-값< >형식이므로 앞 부분만 찾아냄"
		foreach($arr as $key => $value)
		{
			$tmp_arr=explode("-","$key",2);
			if( $tmp_arr[0] > $max_index ) $max_index=$tmp_arr[0];
			
		}
		return ($max_index);
	}

?>

<script language="JavaScript">

function checkInput(form)
{
	//각각의 입력 폼에 입력을 제대로 했는지 검사 하는 함수
	if(!form.in_str_name.value){ 
	alert("이름을 입력하세요.");
	form.in_str_name.focus();//부적절한 입력을 하면 해당 입력 폼에
				//커서를 놓음
	return (false);
	}
	
	if(!form.in_str_contents.value){ 
	alert("내용을 입력하세요.");
	form.in_str_contents.focus();
	return (false);
	}
	
	if(!form.in_str_passwd.value){ 
	alert("비밀 번호를 입력하세요.");
	form.in_str_passwd.focus();
	return (false);
	}
	return (true)
}

function checkInput_del(form)
{

	if(!form.in_del_num.value){ 
	alert("게시물 번호를 입력하세요.");
	form.in_str_passwd.focus();
	return (false);
	}

	if(!form.in_del_pass.value){ 
	alert("비밀 번호를 입력하세요.");
	form.in_str_passwd.focus();
	return (false);
	}
	return (true);
}

</script>

<!--  ************************  STYLE ************************* -->



</head>
<body > 


<!-- 방명록의 내용을 입력 시키는 폼
메시지 전달 방식은 post이며 submit 되면 db_write.php가 실행 됨-->

<form name="input_form" method ="post" action="db_write.php" 
		onSubmit="return checkInput(this)">
  <table width=570 align=center>
  <tr>
      <td align=center colspan=3>
          <font face="휴먼모음T" size=5>방 명 록</font>
      </td>
  </tr>
  <tr>
      <td colspan=3>&nbsp;</td>
  </tr>
  <tr>
      <td colspan=3>&nbsp;</td>
  </tr>
  <tr bgcolor=#afbab9>
      <td align=center><tt><b>이름<b></tt></td>
      <td align=center><tt><b>내용</b></tt></td>
  </tr>
  <tr>
      <td> <input type = "text" name = in_str_name size=12>  </td>
      <td> <input type = "text" name = in_str_contents size=65>  </td>
  </tr>
  <tr>
      <td bgcolor=#d9d9f3 align=center> <b><tt>비밀번호</tt></b> </td>
      
      <td align=left><input type = "password" name = in_str_passwd
	                       size=10    style="font-size=12"></td>	 
  </tr>
  <tr>
      <td>&nbsp;</td>
      <td colspan=2 align=right>
          <input type="submit" value="등록" style="font-size:12;">
          <input type="reset" value="취소" style="font-size:12;">
      </td>
  </tr>
  </table>
</form>

<!-- 방명록의 내용을 출력 하고 삭제 시키는 폼
 인자 전달 방식은 post이며 "삭제"가  submit 되면 db_del.php가 실행 됨-->

<form name="output_form" method="post" action="db_del.php"
		onSubmit="return checkInput_del(this)">
 <table width=700 align=center>
  <tr>
      <td colspan=5>&nbsp;</td>

       <?php   //파일 데이터 베이스로 부터 방명록의 내용을 뿌려 주는 부분

       if( file_exists("file_db"))
       {
	     $metastr=get_meta_tags("file_db");
	     $metastr_len=find_max_index($metastr);
  
	     for($i=1 ; $i<= $metastr_len ;$i++)
	     {
	       //검색을 위한 키값을 구성.
	       $key_name=sprintf("%d-name",$i);
	       $key_con=sprintf("%d-con",$i);
	       $key_pass=sprintf("%d-pass",$i);
	       $key_del=sprintf("%d-del",$i);
	       
	       //임시 삭제 여부를 검사  ** 본 방명록에서는 매 삭제시 마다
	       //파일에서 삭제하는 것이 아니라 삭제 게시물을 휴지통에 모아 두었
	       //다가 한번에 화일의 내용을 몰아서 수정함
	       if( $metastr[$key_del] != 1 ) // 휴지통에 있는 게시물인지 검사
	       {
	       	   //번갈아 가며 배경색을 바꿔 줌
//		   if( ($i%2) == 0 ) echo (" <tr bgcolor=#dde2d1> ");
//	           echo (" <tr bgcolor=#Ebeeee > ");
		   //파일에서 읽어 드려온 게시물 내용을 출력
		 
         ?>
      <tr bgcolor=#EBEEEE >
	 <table border=0 width=600 cellpadding=0 cellspacing=0>
         <tr>
            <td><img src=http://i3.cgiworld.net:8080/g/iconset/MONO/t.gif
	         border=0 usemap="#t80"></td>
         </tr>
         <tr>
            <td align=left 
	        background=http://i3.cgiworld.net:8080/g/iconset/MONO/m.gif>
                <?PHP
		   echo("
		   <p><tt>$i</tt></p>
	           <p><tt>$metastr[$key_name]</tt></p>
	           <p><tt> $metastr[$key_con]
	           </tt></p>");
                 ?>
            </td>
         </tr>
         <tr>
            <td><img src=http://i3.cgiworld.net:8080/g/iconset/MONO/b.gif></td>
         </tr>
            <td></td>
         </tr>
      </table>
     </td>
    </tr>
    <tr></tr>
 <p></p>

<?PHP
	  
	       }
	       
	      echo("<tr><td>&nbsp;</td></tr>");
	     
	      echo("<tr><td>&nbsp;</td></tr>");
	      } //for end
	 } //if scope end
?> 
    

  </tr> 
  <tr>
      <td colspan=3>&nbsp;</td>
  </tr>
  <tr>
  </tr>


 
 
  <tr >
      <td > &nbsp;</td>
      <td > &nbsp;</td>
      <td bgcolor=#d9d9f3 align=right>
          <b><tt>삭제  게시물  번호</tt></b>
          <input type = "text" name = in_del_num size=5>
          <b><tt>비밀 번호</tt></b>
          <input type = "password" name = in_del_pass 
	         style="font-size:12;" size=10>
	  <input type="submit" value="삭제" style="font-size:12;" >
       </td>
   </tr>
</table>
</form>



<script language ="JavaScript">
input_form.in_str_name.focus();
</script>


</body>
</html>


