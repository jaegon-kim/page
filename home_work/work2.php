<html>
<head>

<script language = "JavaScript">
  
  //ÀÔ·ÂÀÌ Á¦´ë·Î µÇ¾ú´ÂÁö °Ë»ç ÇÏ´Â ÀÚ¹Ù ½ºÅ©¸³Æ®
  function Check(form)
  {

	form.first.value=1; // submit ½Ã¿¡¸¸ °è»êÀÌ ÀÌ·ï Áö±â À§ÇÑ flag 
	// ÀÔ·ÂÆû ¸ðµÎ¿¡ ÀÔ·ÂÀÌ Á¦´ë·Î ÀÌ·ï Á³´ÂÁö °Ë»ç.
	if( !form.in_st_year.value ||  !form.in_st_month.value ||
	    !form.in_st_day.value || !form.in_end_year.value ||
	    !form.in_end_month.value || !form.in_end_day.value )
	{
		alert("ÀÔ·Â °ªÀ» ¸ðµÎ ÀÔ·ÂÇØ ÁÖ¼¼¿ä.");
		form.in_st_year.focus();
		return (false);
	}
	
	// ÀÔ·Â °ªÀÌ Á¶°ÇÀ» ¸¸Á· ÇÏ´Â Áö °Ë»ç
	if( form.in_st_year.value > form.in_end_year.value )
	{
		alert("³¡³¯Â¥´Â ½ÃÀÛ ³¯Â¥ º¸´Ù Å©°Å³ª °°¾Æ¾ß ÇÕ´Ï´Ù.");
		form.in_st_year.focus();
		return (false);
	}	
       if( form.in_st_year.value < 1980 || 2003 < form.in_end_year.value)
       {	
		alert("Àß¸øµÈ ¹üÀ§ÀÇ  ÀÔ·Â ÀÔ´Ï´Ù.(1980 - 2003)");
	 	form.in_st_year.focus();
		return (false);
        }

}
 
</script>


</head>
<body align=left bgcolor="#8f8fdf" text="ffffff">
		
   <!--ÀÔ·ÂÀ» ¹Þ¾Æ µéÀÌ´Â form-->
   <form name="count_day" mehtod="post" onSubmit="return Check(this)">

	<table border=0 cellspacing=1 cellpadding=5 width=200
	height=50  align=center bgcolor="6f6fd6"><tr><td>
	
	<p align="center">
	<font face="ÈÞ¸Õ¸ðÀ½T">ÇÁ·Î±×·¡¹Ö °úÁ¦ (³¯Â¥¼ö °è»ê)</font>
	</p>
	<!-- ½ÃÀÛ ³¯Â¥ ÀÔ·Â Æû -->
        <p>½ÃÀÛ ³¯Â¥ ÀÔ·Â 
	<hr width=200 align="left">
	<input type = "text" name = "in_st_year" size=4>³â
	<input type = "text" name = "in_st_month" size=2>¿ù
	<input type = "text" name = "in_st_day" size=2>ÀÏ
	
        <!-- ³¡ ³¯Â¥ ÀÔ·Â Æû... -->	
	<p> ³¡ ³¯Â¥ ÀÔ·Â
	<hr width=200 align="left">
	<input type = "text" name = "in_end_year" size=4>³â
	<input type = "text" name = "in_end_month" size=2>¿ù
	<input type = "text" name = "in_end_day" size=2>ÀÏ
	
	<input type = "hidden" name = "first" value=0 >	
	<p><input type = "submit" value="°á°ú º¸±â" 
	          style="font-size=12" ><p>
	
	<hr width=200 align="left">
	°è»êµÈ ÃÑ ÀÏ¼ö´Â Ï

<!-- ********************** Start PHP code *********************** -->

<?php
	//³¯Â¥ °è»ê ÇÔ¼ö
	function Date_Calc($start_d,$end_d)
	{
		$day_sum =0 ;
		//³âµµ°¡ °°À» °æ¿ì
		if( $start_d[year] == $end_d[year] )
		{
			//´ÜÁö Â÷ÀÌ¸¸À¸·Î Áö³­ ³¯ ¼ö°¡ °è»ê µÊ
			$day_sum=$end_d[yday] - $start_d[yday] + 1;
		}
		else
		{
			//³âµµ°¡ ¼­·Î ´Ù¸¦ °æ¿ì
			//½ÃÀÛ ³¯Â¥ ÀÌÈÄ¿Í Áß°£ ³âµµÀÇ ³¯Â¥ ³¡ ³¯Â¥ ±îÁöÀÇ 
			// ³¯¼ö¸¦ ´õÇÏ¿© °è»ê
			for( $i= $start_d[year]+1 ;$i < $end_d[year]; $i++)
			{
			  //Áß°£ ³âµµÀÇ °¢ ³¯ ¼ö¸¦ ´õÇÔ
			  $year_date = getdate(mktime
			  	(1,1,1,12,31,$i));
				$day_sum+=($year_date[yday]+1);
			 //+1Àº [yday]ÀÇ ¹üÀ§°¡ 0-365·Î Ç¥ÇöµÇ±â ¶§¹®¿¡ ÇÊ¿äÇÑ
			 // º¸Á¤Ä¡
			}
	
			$year_date = getdate(mktime
				(1,1,1,12,31,$start_d[year]));
			$day_sum=$day_sum+($end_d[yday]+1)+
				($year_date[yday]-$start_d[yday]+1);

		}
	
			echo "                      $day_sum ÀÏ";
			return $day_sum;
       }
	
		
	// timestamp¸¦ ¸¸µé¾î ÁÖ°í °¢°¢¿¡ ´ëÇÏ¿© getdate¸¦ ÇÏ¿©
	// ÇØ´ç ³âµµÀÇ yday¸¦ ÀÌ¿ëÇÏ¿© ³¯Â¥ ¼ö¸¦ °è»êÇÔ
	
	$start_date = getdate(mktime
		(1,1,1,$in_st_month,$in_st_day,$in_st_year));
	$end_date = getdate(mktime
		(1,1,1,$in_end_month,$in_end_day,$in_end_year));
	
	
	if( $first == 1)
	{
	Date_Calc( $start_date, $end_date);	
	}
?>
<!-- *********************** end PHP code ********************* -->

       </td>
     </tr>
     </table>

   </form>

<a href='#' onClick='self.close()' ><center><tt>[´Ý±â]</tt></center></a>
<script language="JavaScript">
<!-- document.count_day.in_st_year.focus() //-->
</script>
 


</body>
</html>
		

