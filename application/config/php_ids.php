<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

/*
|--------------------------------------------------------------------------
| Define the url to the PHPIDS 'IDS' folder
|--------------------------------------------------------------------------
|
| You can download the latest version of PHPIDS @ http://php-ids.org/downloads/
| The 'IDS' folder is found in the 'lib' folder from the PHPIDS download. 
|
| Typically PHPIDS will be located in your third_party folder
| 
| URL to the 'IDS' folder, WITH a trailing slash: 
| $config['ids_url'] = APPPATH . 'third_party/phpids/';.
|
*/
$config['ids_url'] = APPPATH . 'third_party/phpids/';

/*
|--------------------------------------------------------------------------
| Define the user ID
|--------------------------------------------------------------------------
|
| If an intrusion from a logged in user is detected we would like to store
| the user ID in the intrusions table. Obviously we also need it for the
| disabling account reaction. We try to grab the user ID from the session.
| If the session value for the user ID in your application is not user_id
| you should update this setting. 
|
*/
$config['user_id'] = 'user_id';

/*
|--------------------------------------------------------------------------
| Define the name of the intrusions table
|--------------------------------------------------------------------------
|
| You can set this to whatever you want as long as you update the table name
| in your database aswell, d0h ;)
|
*/
$config['intrusions_table'] = 'phpids_intrusions';

/*
|--------------------------------------------------------------------------
| Define the name of the bans table
|--------------------------------------------------------------------------
|
| You can set this to whatever you want as long as you update the table name
| in your database aswell, d0h ;)
|
*/
$config['bans_table'] = 'phpids_bans';

/*
|--------------------------------------------------------------------------
| Define the name of the disabled accounts table
|--------------------------------------------------------------------------
|
| You can set this to whatever you want as long as you update the table name
| in your database aswell, d0h ;)
|
*/
$config['disabled_table'] = 'phpids_disabled_accounts';

/*
|--------------------------------------------------------------------------
| Define the duration for the ip ban
|--------------------------------------------------------------------------
*/
$config['ban_duration'] = array(
    'seconds' => 0, 
    'minutes' => 10, 
    'hours' => 0, 
    'days' => 0, 
    'months' => 0, 
    'years' => 0, 
    );

/*
|--------------------------------------------------------------------------
| Define the duration for the disabled account
|--------------------------------------------------------------------------
*/
$config['disabled_duration'] = array(
    'seconds' => 0, 
    'minutes' => 10, 
    'hours' => 0, 
    'days' => 0, 
    'months' => 0, 
    'years' => 0, 
    );

/*
|--------------------------------------------------------------------------
| Define the thresholds for the IDS reactions (0 = disabled)
|--------------------------------------------------------------------------
|
*/
$config['treshold'] = array(
    'log' => 1, 
    'warn' => 5, 
    'mail' => 40, 
    'kill' => 0, 
    'disable_account' => 0, 
    'ban_ip' => 0,
    'text' => 0
    );

/*
|--------------------------------------------------------------------------
| Define the warning message
|--------------------------------------------------------------------------
|
*/
$config['message_warning'] = 'Your input contains malicious input, please stop that!';

/*
|--------------------------------------------------------------------------
| Define the email address for mailing
|--------------------------------------------------------------------------
|
*/
$config['email_address'] = '';

/*
|--------------------------------------------------------------------------
| Define the phone number for texting
|--------------------------------------------------------------------------
|
*/
$config['text'] = '';

/*
|--------------------------------------------------------------------------
| Define here if you want to check the user agent string. PHPIDS allows us
| to also check the user agent string for malicious input but this function
| has a lot of false positives.
|--------------------------------------------------------------------------
|
*/
$config['check_user_agent'] = FALSE;

/* End of file php_ids.php */
/* Location: ./application/config/php_ids.php */
