<?php
/*
// *********************************
// Based on code originally written by Smurf_Minions (http://guildwarsholland.nl/)
// Modified by sklerder (sklerder -at- orange.fr)
// Last Modified: 2012/11/26
// Version 1.0.6
// *********************************
*/
define('NOT_SPAM', 0);
define('HONEYPOT_SPAM', 1);
define('BLACKLIST_SPAM', 2);
define('DNSBL_SPAM', 3);


//
// Log registration details
//
function log_register_details($email, $membersIP, $req_username, $spam, $botcheck, $info)
{
	/*
	This function log the details on the registration attempt (details concerning the user)
	*/

	global $db;
	global $timezone;
	global $email_setting;
	global $errors;







	// Log the register attempt
 	$db->query('INSERT INTO '.$db->prefix.'test_registrations (username, email, email_setting, timezone, ip, referer, user_agent, date, spam, s_errors, count_errors, botcheck, infos) VALUES(\''.$db->escape($req_username).'\', \''.$db->escape($email).'\', '.$email_setting.', '.$timezone.', \''.get_remote_address().'\', \''.$db->escape($_SERVER['HTTP_REFERER']).'\', \''.$db->escape($_SERVER['HTTP_USER_AGENT']).'\', '.time().', '.$spam.', \''.$db->escape($s_errors).'\', '.count($errors).', '.$botcheck.', \''.$db->escape($info).'\')') or error('Unable to log user registration', __FILE__, __LINE__, $db->error());


}
//
// End Log registration details
//




//
// BEGIN check DNSBL
//

function sb_check_dnsbl($ipAddress, $username)
{
/*
// It might be interesting to weight the results based on the number of servers surveyed
*/
	// $dnsbl = 'sbl.spamhaus.org, xbl.spamhaus.org, b.barracudacentral.org, opm.tornevall.org';
	global $pun_config;
	$email = '';
	$dnsbl = $pun_config['o_sb_dnsbl_names'];
	$dnsbl_lists = explode(",", preg_replace('/\s+/', '', $dnsbl));
	$reverse_ip = implode(".", array_reverse(explode(".", $ipAddress)));
	$check = 0;
	$count = 0;
	$attempt = '(';

	foreach($dnsbl_lists as $list)
	{
		if (checkdnsrr($reverse_ip.".".$list.".", "A"))
		{
			$check = 11;
			$ckdnsflag = 1;
		}
		else
		{
			$ckdnsflag = 0;
		}
		$count += 1;
		($count > 1) ? $attempt .= ',' : '';
		$attempt .= $list.':'.$ckdnsflag;
	}

	$attempt .= ')';
	$result=array('check' => $check, 'attempt' => $attempt);
	return $result;
}

//
// END check DNSBL
//

//
// CheckStopForumSpam BEGIN
//

function sb_stopforumspam_check($emailAddress, $ipAddress, $user_Name)
{
/*
// ReturnCodes :
// 0 : Not flagged as spam
// 1 : IP registered at SFS
// 2 : Email registered at SFS
// 3 : Username registered at SFS (not used)
// 4 : Service unavailable
// 5 : IP & Email not set
// 6 : Undefined result
*/

  // Initiate and declare spambot as value 0 - as we are just getting started
  $spambot = 0;
	if ((!$ipAddress == "" ) || (!$emailAddress == ""))
	{
		$url = 'https://www.stopforumspam.com/api?ip='. $ipAddress .'&email='. $emailAddress .'&username=' . $user_Name .'&f=json';
		$data1 = @file_get_contents($url);
		$data = json_decode($data1);

		// First, check if SFS server is up
		if((isset($data->error)) or ($data == Null))
		{
			if($data == Null)
			{
				$spambot = 4;
				$error = 'StopForumSpam.com could not be reached';
			}
			else
			{
				$spambot = 6;
				$error = $data->error;
			}
		}
		else
		{
			// Verify IP, and Email if necessary (Username won't be verified, too many false positive)
			if(($data->ip->appears)){
				$spambot = 1;
				$error=$data1;
			}
			else if(($data->email->appears)){
				$spambot = 2;
				$error=$data1;
			}
		}
	}
	else
	{
		$spambot = 5;
		$error='Neither IP nor Email are set, unable to perform check!';
	}
	$result=array('check' => $spambot, 'attempt' => $error);
	return $result; // Return test results as value

}

//
// CheckStopForumSpam END
//

//
// Report a spammer to stopforumspam database
//
function sb_stopforumspam_report($ip, $email, $user_Name, $evidence)
{
	global $pun_config;
	$evidency = 'Spammer manually detected, but automatically reported.';

	// Do not report if there is no StopForumSpam API key
	if ($pun_config['o_sb_sfs_api_key'] == '')
		return false;

	if (empty($evidence))
	$evidence = $evidency ;

	$context = stream_context_create(array('http' => array(
		'method'	=> 'POST',
		'header'	=> 'Content-type: application/x-www-form-urlencoded',
		'content'	=> http_build_query(array(
			'ip_addr'	=> $ip,
			'email'		=> $email,
			'username'	=> $user_Name,
			'evidence'	=> $evidence,
			'api_key'	=> $pun_config['o_sb_sfs_api_key'],
		)),
	)));

	return @file_get_contents('https://www.stopforumspam.com/add', false, $context) ? true : false;
}

// Check registration attempt
function sb_check_spam_registration($req_username,$email)
{
	global $pun_config;
	global $pun_user;
	global $timezone;
	global $email_setting;
	global $db;
	$botcheck = 0;
	$membersIP = get_remote_address();
	$spam = NOT_SPAM;
	$status = '';

	if (!empty($_POST['req_user']) && ($pun_config['o_sb_check_hp'] == '1'))
	{
		$spam = HONEYPOT_SPAM;
		$botcheck = 3;
		$evidence = 'Automated registration detected.';
		$status = serialize($_POST);
	}

	if ($botcheck == 0)
	{
		if ($pun_config['o_sb_check_sfs_register'] == '1')
		{
			$result = sb_stopforumspam_check($email, $membersIP, $req_username);
			$botcheck=$result['check'];
			$status=$result['attempt'];

			if ($botcheck == 1 || $botcheck == 2)
			{
				$spam = BLACKLIST_SPAM;

				$evidence = "";
			}
		}
	}

	if ((($pun_config['o_sb_check_sfs_register'] == '0') && ($botcheck == 0)) || ($botcheck > 3))
	{
		if ($pun_config['o_sb_check_dnsbl_register'] == '1')
		{
			$result= sb_check_dnsbl($membersIP, $req_username);
			$botcheck=$result['check'];
			if ($botcheck == 11)
			{
				$spam = DNSBL_SPAM;
				$status=$result['attempt'];
				$evidence = ""; // We do not report, because DNSBL have latency that could interfere with "whitelisting".
			}
		}
	}

	// Add detailed members info in  PUN_ROOT.spam/{date}_register.log
	log_register_details($email, pun_htmlspecialchars($membersIP), $req_username, $spam, $botcheck, $status);

  	if ($spam != NOT_SPAM)
  	{
   		// Since we found a spammer, lets report him to SFS !
		if (!empty($evidence) && ($pun_config['o_sb_sfs_report'] == '1'))
		{
			sb_stopforumspam_report($membersIP, $email, $req_username, $evidence);
		}


		if (file_exists(PUN_ROOT.'lang/'.$pun_user['language'].'/spambarrier.php'))
			require PUN_ROOT.'lang/'.$pun_user['language'].'/spambarrier.php';
		else
			require PUN_ROOT.'lang/English/spambarrier.php';




		switch ($botcheck)
		{
			case 1:
			case 11:
				message($lang_spambarrier['potentiallyUnwantedPeople'].' RC : 1');
				break;
			case 2:
				message($lang_spambarrier['potentiallyUnwantedPeople'].' RC : 2');
				break;
			case 3:
				 message($lang_spambarrier['potentiallyUnwantedPeople'].' RC : 3');
				break;
/* 			case 4:
				// message($lang_spambarrier['serverProblem']);
				break;
			case 5:
				// message($lang_spambarrier['technicalProblem']);
				break;
			case 6:
				// message($lang_spambarrier['Undefined conditions']);
				break; */
		}
  		message($lang_spambarrier['Spam_catch'].' <a href="mailto:'.$pun_config['o_admin_email'].'">'.$pun_config['o_admin_email'].'</a>.');
  	}
}

// Check login attempt
// Login will not be accepted if the user or his IP is listed at SFS or DNSBL, but authorized if no answer from the SFS and DNSBL services.
function sb_check_spam_login($membersIP,$username,$email)
{
	global $pun_config;
	global $pun_user;
	$spam = NOT_SPAM;
	$botcheck = 0;

	if ($pun_config['o_sb_check_sfs_login'] == '1')
	{
		$result = sb_stopforumspam_check($email, $membersIP, $username);

		$botcheck=$result['check'];
		$status=$result['attempt'];
	}

	if (($botcheck == 1) || ($botcheck == 2))
	{
		$spam = BLACKLIST_SPAM;
	}
	else
	{
		if ($pun_config['o_sb_check_dnsbl_login'] == '1')
		{
			$result = sb_check_dnsbl($membersIP, $username);
			$botcheck=$result['check'];

			if ($botcheck == 11)
			{
				$spam = DNSBL_SPAM;
				$status=$result['attempt'];
			}
		}
	}

		if (file_exists(PUN_ROOT.'lang/'.$pun_user['language'].'/spambarrier.php'))
			require PUN_ROOT.'lang/'.$pun_user['language'].'/spambarrier.php';
		else
			require PUN_ROOT.'lang/English/spambarrier.php';

		switch ($botcheck)
		{
			case 1:
			case 11:
				message($lang_spambarrier['potentiallyUnwantedPeople'].' RC : 1');
				break;
			case 2:
				message($lang_spambarrier['potentiallyUnwantedPeople'].' RC : 2');
				break;
			case 3:
				// message($lang_spambarrier['potentiallyUnwantedPeople'].' RC : 3');
				break;
			case 4:
				// message($lang_spambarrier['serverProblem']);
				break;
			case 5:
				// message($lang_spambarrier['technicalProblem']);
				break;
			case 6:
				// message($lang_spambarrier['Undefined conditions']);
				break;
		}
}

//
// Check if a string is contained in another string
//
function contains($str, $content, $ignorecase = true)
{
	if ($ignorecase)
	{
		$str = strtolower($str);
		$content = strtolower($content);
	}

	return (strpos($content, $str) !== false) ? true : false;
}

?>
