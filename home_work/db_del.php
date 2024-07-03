<?php
	if( file_exists("file_db"))
	{
	   $metastr=get_meta_tags("file_db");
	
	   $pass_key=sprintf("%d-pass",$in_del_num);

	   if($in_del_pass == $metastr[$pass_key])
	   {  	
		$fp=fopen("file_db","a+");
		$del_str=sprintf("<meta name=\"%d-del\" content=1>"
					,$in_del_num);
		fwrite($fp,$del_str,strlen($del_str));
		fclose($fp);
	   }	
	   else
	   {
		echo("
			<script language='JavaScript'>
	 		alert(' 잘못된 비밀 번호입니다.');
	 		</script>");
	   }
	 }
	 else
	 {
		echo("
		<script language='JavaScript'>
	 		alert(' 삭제할 게시물이 없습니다.');
	 	</script>");
	 }
	
		
	
	echo("
		<script language='JavaScript'>
			location='visiting_board.php'
		</script>
	");
	

?>
	
