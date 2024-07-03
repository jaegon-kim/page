<html>
<head>

<script language = "JavaScript">
  
  //입력이 제대로 되었는지 검사 하는 자바 스크립트
  function Check(form)
  {

	form.first.value=1; // submit 시에만 계산이 이뤄 지기 위한 flag 
	// 입력폼 모두에 입력이 제대로 이뤄 졌는지 검사.
	if( !form.in_st_year.value ||  !form.in_st_month.value ||
	    !form.in_st_day.value || !form.in_end_year.value ||
	    !form.in_end_month.value || !form.in_end_day.value )
	{
		alert("입력 값을 모두 입력해 주세요.");
		form.in_st_year.focus();
		return (false);
	}
	
	// 입력 값이 조건을 만족 하는 지 검사
	if( form.in_st_year.value > form.in_end_year.value )
	{
		alert("끝날짜는 시작 날짜 보다 크거나 같아야 합니다.");
		form.in_st_year.focus();
		return (false);
	}	
       if( form.in_st_year.value < 1980 || 2003 < form.in_end_year.value)
       {	
		alert("잘못된 범위의  입력 입니다.(1980 - 2003)");
	 	form.in_st_year.focus();
		return (false);
        }

}
 
</script>


</head>
<body align=left bgcolor="#8f8fdf" text="ffffff">
		
   <!--입력을 받아 들이는 form-->
   <form name="count_day" mehtod="post" onSubmit="return Check(this)">

	<table border=0 cellspacing=1 cellpadding=5 width=200
	height=50  align=center bgcolor="6f6fd6"><tr><td>
	
	<p align="center">
	<font face="휴먼모음T">프로그래밍 과제 (날짜수 계산)</font>
	</p>
	<!-- 시작 날짜 입력 폼 -->
        <p>시작 날짜 입력 
	<hr width=200 align="left">
	<input type = "text" name = "in_st_year" size=4>년
	<input type = "text" name = "in_st_month" size=2>월
	<input type = "text" name = "in_st_day" size=2>일
	
        <!-- 끝 날짜 입력 폼... -->	
	<p> 끝 날짜 입력
	<hr width=200 align="left">
	<input type = "text" name = "in_end_year" size=4>년
	<input type = "text" name = "in_end_month" size=2>월
	<input type = "text" name = "in_end_day" size=2>일
	
	<input type = "hidden" name = "first" value=0 >	
	<p><input type = "submit" value="결과 보기" 
	          style="font-size=12" ><p>
	
	<hr width=200 align="left">
	계산된 총 일수는 �

<!-- ********************** Start PHP code *********************** -->

<?php
	//날짜 계산 함수
	function Date_Calc($start_d,$end_d)
	{
		$day_sum =0 ;
		//년도가 같을 경우
		if( $start_d[year] == $end_d[year] )
		{
			//단지 차이만으로 지난 날 수가 계산 됨
			$day_sum=$end_d[yday] - $start_d[yday] + 1;
		}
		else
		{
			//년도가 서로 다를 경우
			//시작 날짜 이후와 중간 년도의 날짜 끝 날짜 까지의 
			// 날수를 더하여 계산
			for( $i= $start_d[year]+1 ;$i < $end_d[year]; $i++)
			{
			  //중간 년도의 각 날 수를 더함
			  $year_date = getdate(mktime
			  	(1,1,1,12,31,$i));
				$day_sum+=($year_date[yday]+1);
			 //+1은 [yday]의 범위가 0-365로 표현되기 때문에 필요한
			 // 보정치
			}
	
			$year_date = getdate(mktime
				(1,1,1,12,31,$start_d[year]));
			$day_sum=$day_sum+($end_d[yday]+1)+
				($year_date[yday]-$start_d[yday]+1);

		}
	
			echo "                      $day_sum 일";
			return $day_sum;
       }
	
		
	// timestamp를 만들어 주고 각각에 대하여 getdate를 하여
	// 해당 년도의 yday를 이용하여 날짜 수를 계산함
	
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

<a href='#' onClick='self.close()' ><center><tt>[닫기]</tt></center></a>
<script language="JavaScript">
<!-- document.count_day.in_st_year.focus() //-->
</script>
 


</body>
</html>
		

